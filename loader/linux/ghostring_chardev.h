/* GhostRing Hypervisor — Author: Baurzhan Atynov <bauratynov@gmail.com> — MIT License */

#ifndef GHOSTRING_CHARDEV_H
#define GHOSTRING_CHARDEV_H

int  gr_chardev_init(void);
void gr_chardev_exit(void);
void gr_alert_push(u32 cpu, u32 type, u64 info);

#endif /* GHOSTRING_CHARDEV_H */
