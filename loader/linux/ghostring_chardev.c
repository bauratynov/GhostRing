/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include "ghostring_chardev.h"

/* ---------------------------------------------------------------------------
 * Ioctl commands
 * ------------------------------------------------------------------------- */

#define GR_IOC_MAGIC           'G'
#define GR_IOC_STATUS          _IOR(GR_IOC_MAGIC, 1, int)
#define GR_IOC_CPU_COUNT       _IOR(GR_IOC_MAGIC, 2, int)
#define GR_IOC_INTEGRITY_CHECK _IO(GR_IOC_MAGIC,  3)

/* ---------------------------------------------------------------------------
 * Alert ring buffer
 * ------------------------------------------------------------------------- */

#define GR_ALERT_RING_SIZE     64

typedef struct gr_alert {
	u64  timestamp_ns;
	u32  cpu_id;
	u32  alert_type;
	u64  info;
} gr_alert_t;

static gr_alert_t       gr_ring[GR_ALERT_RING_SIZE];
static unsigned int      gr_ring_head;     /* next write position */
static unsigned int      gr_ring_tail;     /* next read position  */
static DEFINE_SPINLOCK(gr_ring_lock);

static DECLARE_WAIT_QUEUE_HEAD(gr_wait_queue);

/* ---------------------------------------------------------------------------
 * Ring buffer helpers (called from vmexit context with ring_lock held)
 * ------------------------------------------------------------------------- */

void gr_alert_push(u32 cpu, u32 type, u64 info)
{
	unsigned long flags;

	spin_lock_irqsave(&gr_ring_lock, flags);

	gr_ring[gr_ring_head].timestamp_ns = ktime_get_ns();
	gr_ring[gr_ring_head].cpu_id       = cpu;
	gr_ring[gr_ring_head].alert_type   = type;
	gr_ring[gr_ring_head].info         = info;

	gr_ring_head = (gr_ring_head + 1) % GR_ALERT_RING_SIZE;

	/* If full, advance tail (drop oldest) */
	if (gr_ring_head == gr_ring_tail)
		gr_ring_tail = (gr_ring_tail + 1) % GR_ALERT_RING_SIZE;

	spin_unlock_irqrestore(&gr_ring_lock, flags);

	wake_up_interruptible(&gr_wait_queue);
}
EXPORT_SYMBOL_GPL(gr_alert_push);

static int gr_ring_empty(void)
{
	return gr_ring_head == gr_ring_tail;
}

/* ---------------------------------------------------------------------------
 * File operations
 * ------------------------------------------------------------------------- */

static int gr_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int gr_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t gr_read(struct file *filp, char __user *buf,
		       size_t count, loff_t *ppos)
{
	gr_alert_t alert;
	unsigned long flags;
	int rc;

	if (count < sizeof(gr_alert_t))
		return -EINVAL;

	/* Block until an alert is available */
	if (filp->f_flags & O_NONBLOCK) {
		if (gr_ring_empty())
			return -EAGAIN;
	} else {
		rc = wait_event_interruptible(gr_wait_queue, !gr_ring_empty());
		if (rc)
			return rc;
	}

	spin_lock_irqsave(&gr_ring_lock, flags);
	if (gr_ring_empty()) {
		spin_unlock_irqrestore(&gr_ring_lock, flags);
		return 0;
	}
	alert = gr_ring[gr_ring_tail];
	gr_ring_tail = (gr_ring_tail + 1) % GR_ALERT_RING_SIZE;
	spin_unlock_irqrestore(&gr_ring_lock, flags);

	if (copy_to_user(buf, &alert, sizeof(alert)))
		return -EFAULT;

	return sizeof(alert);
}

static long gr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int val;

	switch (cmd) {
	case GR_IOC_STATUS:
		val = 1; /* running */
		if (copy_to_user((int __user *)arg, &val, sizeof(val)))
			return -EFAULT;
		return 0;

	case GR_IOC_CPU_COUNT:
		val = num_online_cpus();
		if (copy_to_user((int __user *)arg, &val, sizeof(val)))
			return -EFAULT;
		return 0;

	case GR_IOC_INTEGRITY_CHECK:
		/* TODO Phase 2: trigger integrity scan across all CPUs */
		pr_info("GhostRing: integrity check requested\n");
		return 0;

	default:
		return -ENOTTY;
	}
}

static const struct file_operations gr_fops = {
	.owner          = THIS_MODULE,
	.open           = gr_open,
	.release        = gr_release,
	.read           = gr_read,
	.unlocked_ioctl = gr_ioctl,
};

/* ---------------------------------------------------------------------------
 * Device registration
 * ------------------------------------------------------------------------- */

static dev_t         gr_devno;
static struct cdev   gr_cdev;
static struct class *gr_class;

int gr_chardev_init(void)
{
	int rc;

	rc = alloc_chrdev_region(&gr_devno, 0, 1, "ghostring");
	if (rc)
		return rc;

	cdev_init(&gr_cdev, &gr_fops);
	gr_cdev.owner = THIS_MODULE;
	rc = cdev_add(&gr_cdev, gr_devno, 1);
	if (rc)
		goto err_region;

	gr_class = class_create("ghostring");
	if (IS_ERR(gr_class)) {
		rc = PTR_ERR(gr_class);
		goto err_cdev;
	}

	if (IS_ERR(device_create(gr_class, NULL, gr_devno, NULL, "ghostring"))) {
		rc = -ENOMEM;
		goto err_class;
	}

	pr_info("GhostRing: /dev/ghostring created (major %d)\n", MAJOR(gr_devno));
	return 0;

err_class:
	class_destroy(gr_class);
err_cdev:
	cdev_del(&gr_cdev);
err_region:
	unregister_chrdev_region(gr_devno, 1);
	return rc;
}

void gr_chardev_exit(void)
{
	device_destroy(gr_class, gr_devno);
	class_destroy(gr_class);
	cdev_del(&gr_cdev);
	unregister_chrdev_region(gr_devno, 1);
	pr_info("GhostRing: /dev/ghostring removed\n");
}
