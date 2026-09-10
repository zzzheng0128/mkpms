#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H
#include <linux/spinlock.h>

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};

#endif /* _LINUX_WAIT_H */