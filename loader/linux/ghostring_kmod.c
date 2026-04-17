/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> */
/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/preempt.h>
#include <linux/sched.h>     /* current, init_mm */
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/io.h>          /* virt_to_phys, phys_to_virt */
#include <asm/pgtable.h>     /* init_mm.pgd */

#include "ghostring_chardev.h"
#include "gr_types.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Baurzhan Atynov <bauratynov@gmail.com>");
MODULE_DESCRIPTION("GhostRing Hypervisor — Linux kernel module loader");
MODULE_VERSION("0.1.0");

/* Bridge to the core runtime flag defined in src/common/globals.c. */
extern int g_allow_nested;

/*
 * allow_nested — when 1, GhostRing will enter VMX root mode even when
 * CPUID reports another hypervisor is present (i.e. we are running inside
 * a VirtualBox / KVM / VMware guest with nested VT-x enabled).  Intended
 * for development and CI; leave at 0 on production systems.
 */
static int allow_nested = 0;
module_param(allow_nested, int, 0644);
MODULE_PARM_DESC(allow_nested,
    "Enter VMX root even if an outer hypervisor is detected (default: 0)");

/* ---------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

#define GR_CPUID_VENDOR_INTEL   0x01
#define GR_CPUID_VENDOR_AMD     0x02

#define GR_PAGE_POOL_ORDER      8          /* 2^8 = 256 contiguous pages      */
#define GR_PAGE_POOL_PAGES      (1 << GR_PAGE_POOL_ORDER)
#define GR_BITMAP_LONGS         (GR_PAGE_POOL_PAGES / BITS_PER_LONG)

/* Magic CPUID leaf used to ask GhostRing to shut down on current CPU         */
#define GR_CPUID_EXIT_LEAF      0x47520001 /* "GR\x00\x01"                    */

/* CPUID feature bits                                                         */
#define CPUID_1_ECX_VMX         (1U << 5)
#define CPUID_8_ECX_SVM         (1U << 2)

/* IA32_FEATURE_CONTROL bits                                                  */
#define IA32_FEATURE_CONTROL          0x3A
#define FEATURE_CONTROL_LOCKED        (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE (1ULL << 2)

/*
 * Per-CPU vCPU state is managed by the core via src/common/vcpu.h.
 * The kmod accesses it through gr_get_vcpu() / gr_set_vcpu().
 * No local definition — avoids struct conflict with vcpu.h.
 */

/* ---------------------------------------------------------------------------
 * Module-wide state
 * ------------------------------------------------------------------------- */

static int               gr_cpu_vendor;
static int               gr_nr_cpus;
static gr_vcpu_t       **gr_vcpus;         /* per-CPU array                   */

/* Simple page-pool with bitmap allocator                                     */
static struct page      *gr_pool_base;
static void             *gr_pool_va;
static unsigned long     gr_pool_bitmap[GR_BITMAP_LONGS];
static DEFINE_SPINLOCK(gr_pool_lock);

/* ---------------------------------------------------------------------------
 * Page pool helpers
 * ------------------------------------------------------------------------- */

static void *gr_pool_alloc_page(void)
{
	unsigned long bit;
	void *va = NULL;

	spin_lock(&gr_pool_lock);
	bit = find_first_zero_bit(gr_pool_bitmap, GR_PAGE_POOL_PAGES);
	if (bit < GR_PAGE_POOL_PAGES) {
		set_bit(bit, gr_pool_bitmap);
		va = gr_pool_va + (bit << PAGE_SHIFT);
	}
	spin_unlock(&gr_pool_lock);
	return va;
}

static void gr_pool_free_page(void *va)
{
	unsigned long off, bit;

	if (!va)
		return;
	off = (unsigned long)va - (unsigned long)gr_pool_va;
	bit = off >> PAGE_SHIFT;
	spin_lock(&gr_pool_lock);
	clear_bit(bit, gr_pool_bitmap);
	spin_unlock(&gr_pool_lock);
}

/* ---------------------------------------------------------------------------
 * CPU vendor / feature detection
 * ------------------------------------------------------------------------- */

static int gr_detect_vendor(void)
{
	u32 eax, ebx, ecx, edx;

	cpuid(0, &eax, &ebx, &ecx, &edx);

	/* "GenuineIntel" : ebx=0x756e6547 edx=0x49656e69 ecx=0x6c65746e */
	if (ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e)
		return GR_CPUID_VENDOR_INTEL;

	/* "AuthenticAMD" : ebx=0x68747541 edx=0x69746e65 ecx=0x444d4163 */
	if (ebx == 0x68747541 && edx == 0x69746e65 && ecx == 0x444d4163)
		return GR_CPUID_VENDOR_AMD;

	return 0;
}

static int gr_check_vtx_support(void)
{
	u32 eax, ebx, ecx, edx;
	u64 feat;

	cpuid(1, &eax, &ebx, &ecx, &edx);
	if (!(ecx & CPUID_1_ECX_VMX)) {
		pr_err("GhostRing: VT-x not supported by CPU\n");
		return -ENODEV;
	}

	rdmsrl(IA32_FEATURE_CONTROL, feat);
	if ((feat & FEATURE_CONTROL_LOCKED) &&
	    !(feat & FEATURE_CONTROL_VMXON_OUTSIDE)) {
		pr_err("GhostRing: VT-x disabled in BIOS (IA32_FEATURE_CONTROL)\n");
		return -ENODEV;
	}

	return 0;
}

static int gr_check_svm_support(void)
{
	u32 eax, ebx, ecx, edx;

	cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
	if (!(ecx & CPUID_8_ECX_SVM)) {
		pr_err("GhostRing: AMD SVM not supported by CPU\n");
		return -ENODEV;
	}
	return 0;
}

/* ---------------------------------------------------------------------------
 * Per-CPU initialization via the glue layer.
 *
 * The glue layer (src/common/glue.c) handles all VMX/SVM setup internally.
 * The loader just passes parameters and the glue does the rest.
 * ------------------------------------------------------------------------- */

#include "../../src/common/glue.h"

static gr_init_params_t gr_params;

/*
 * Platform callbacks — bridge between Linux kernel APIs and the
 * freestanding hypervisor core.
 */
static phys_addr_t linux_virt_to_phys(void *va)
{
	return virt_to_phys(va);
}

static void *linux_phys_to_virt(phys_addr_t pa)
{
	return phys_to_virt(pa);
}

static void *linux_alloc_contiguous(uint32_t count)
{
	struct page *p = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(count * PAGE_SIZE));
	return p ? page_address(p) : NULL;
}

static void linux_free_contiguous(void *ptr, uint32_t count)
{
	if (ptr)
		free_pages((unsigned long)ptr, get_order(count * PAGE_SIZE));
}

static void linux_log(const char *msg)
{
	pr_info("GhostRing: %s", msg);
}

static gr_platform_ops_t linux_platform = {
	.virt_to_phys    = linux_virt_to_phys,
	.phys_to_virt    = linux_phys_to_virt,
	.alloc_contiguous = linux_alloc_contiguous,
	.free_contiguous  = linux_free_contiguous,
	.log              = linux_log,
};

static void gr_per_cpu_init(void *arg)
{
	int cpu = smp_processor_id();

	preempt_disable();

	if (gr_init_cpu(&gr_params) == 0) {
		gr_vcpus[cpu]->active = 1;
		pr_info("GhostRing: CPU %d virtualized\n", cpu);
	} else {
		pr_warn("GhostRing: CPU %d failed to virtualize\n", cpu);
	}

	preempt_enable();
}

/* ---------------------------------------------------------------------------
 * Per-CPU teardown — issue magic CPUID so GhostRing exits VMX root mode
 * ------------------------------------------------------------------------- */

static void gr_per_cpu_exit(void *arg)
{
	int cpu = smp_processor_id();
	gr_vcpu_t *vcpu;
	u32 eax, ebx, ecx, edx;

	preempt_disable();

	vcpu = gr_vcpus[cpu];
	if (vcpu && vcpu->active) {
		/* Magic CPUID — intercepted by GhostRing vmexit handler to
		 * execute VMXOFF and return to the caller in non-root mode. */
		eax = GR_CPUID_EXIT_LEAF;
		ecx = 0;
		cpuid(eax, &eax, &ebx, &ecx, &edx);
		vcpu->active = 0;
		pr_info("GhostRing: CPU %d devirtualized\n", cpu);
	}

	preempt_enable();
}

/* ---------------------------------------------------------------------------
 * Module init / exit
 * ------------------------------------------------------------------------- */

static int __init ghostring_init(void)
{
	int cpu, rc;

	pr_info("GhostRing: loading hypervisor module\n");

	/* Propagate module parameter into core runtime flag */
	g_allow_nested = allow_nested;
	if (allow_nested)
		pr_info("GhostRing: allow_nested=1 — will enter VMX root under outer hypervisor\n");

	/* 1. Detect CPU vendor */
	gr_cpu_vendor = gr_detect_vendor();
	if (gr_cpu_vendor == 0) {
		pr_err("GhostRing: unsupported CPU vendor\n");
		return -ENODEV;
	}
	pr_info("GhostRing: detected %s CPU\n",
		gr_cpu_vendor == GR_CPUID_VENDOR_INTEL ? "Intel" : "AMD");

	/* 2. Check virtualisation support */
	if (gr_cpu_vendor == GR_CPUID_VENDOR_INTEL)
		rc = gr_check_vtx_support();
	else
		rc = gr_check_svm_support();
	if (rc)
		return rc;

	/* 3. Allocate per-CPU vCPU structures */
	gr_nr_cpus = num_online_cpus();
	gr_vcpus = kzalloc(gr_nr_cpus * sizeof(*gr_vcpus), GFP_KERNEL);
	if (!gr_vcpus)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		gr_vcpus[cpu] = kzalloc(sizeof(gr_vcpu_t), GFP_KERNEL);
		if (!gr_vcpus[cpu]) {
			rc = -ENOMEM;
			goto err_free_vcpus;
		}
	}

	/* 4. Allocate contiguous page pool */
	gr_pool_base = alloc_pages(GFP_KERNEL | __GFP_ZERO, GR_PAGE_POOL_ORDER);
	if (!gr_pool_base) {
		pr_err("GhostRing: failed to allocate page pool\n");
		rc = -ENOMEM;
		goto err_free_vcpus;
	}
	gr_pool_va = page_address(gr_pool_base);

	/* 5. Clear bitmap (all pages free) */
	memset(gr_pool_bitmap, 0, sizeof(gr_pool_bitmap));

	/* 6. Register platform callbacks and init params */
	gr_platform_register(&linux_platform);

	gr_params.vendor = (gr_cpu_vendor == GR_CPUID_VENDOR_INTEL)
	                 ? GR_CPU_INTEL : GR_CPU_AMD;
	/*
	 * System CR3: use the current task's page table.  For a module
	 * loaded via insmod, current->mm is the insmod process's mm.
	 * For kernel-wide monitoring we'd need init_mm, but that symbol
	 * is not exported to modules.  Use current CR3 read via MSR/asm
	 * instead — works for any context.
	 */
	{
		unsigned long cr3;
		asm volatile("mov %%cr3, %0" : "=r"(cr3));
		gr_params.system_cr3 = cr3;
	}

	/*
	 * Kernel text boundaries — _text and _etext are not exported to
	 * modules since CONFIG_KALLSYMS can expose them via kallsyms_lookup_name
	 * (also no longer exported since 5.7).  For Phase 1 we pass zeros;
	 * the integrity monitor will detect this and skip kernel text
	 * protection until the loader provides real addresses via hypercall.
	 */
	gr_params.kernel_text_start = 0;
	gr_params.kernel_text_size  = 0;

	/* 7. Broadcast VMX init to every online CPU */
	on_each_cpu(gr_per_cpu_init, NULL, 1);

	/* 7. Create /dev/ghostring character device */
	rc = gr_chardev_init();
	if (rc) {
		pr_err("GhostRing: failed to create /dev/ghostring\n");
		goto err_exit_vmx;
	}

	pr_info("GhostRing: hypervisor loaded on %d CPUs\n", gr_nr_cpus);
	return 0;

err_exit_vmx:
	on_each_cpu(gr_per_cpu_exit, NULL, 1);
	__free_pages(gr_pool_base, GR_PAGE_POOL_ORDER);
err_free_vcpus:
	for_each_online_cpu(cpu) {
		kfree(gr_vcpus[cpu]);
	}
	kfree(gr_vcpus);
	return rc;
}

static void __exit ghostring_exit(void)
{
	int cpu, count = 0;

	/* 1. Remove char device first */
	gr_chardev_exit();

	/* 2. Devirtualize all CPUs */
	on_each_cpu(gr_per_cpu_exit, NULL, 1);

	/* 3. Count devirtualized CPUs — actual resource cleanup happens
	 * in the glue layer (gr_shutdown_cpu → gr_set_vcpu(cpu, NULL)).
	 * The core allocations are freed via the platform allocator. */
	for_each_online_cpu(cpu) {
		if (gr_vcpus[cpu]) {
			if (gr_vcpus[cpu]->active == 0)
				count++;
			kfree(gr_vcpus[cpu]);
		}
	}
	kfree(gr_vcpus);

	/* 4. Free page pool */
	if (gr_pool_base)
		__free_pages(gr_pool_base, GR_PAGE_POOL_ORDER);

	pr_info("GhostRing: unloaded from %d CPUs\n", count);
}

module_init(ghostring_init);
module_exit(ghostring_exit);
