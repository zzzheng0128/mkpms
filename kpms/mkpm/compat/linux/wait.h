#ifndef _LINUX_WAIT_H
/* compat shim: KP header 集缺 wait_queue_head 定义。
 * 我们不需要操作 wait queue, 但 poll.h 引用它, 所以这里给个最小定义。 */
#define _LINUX_WAIT_H
#include <linux/spinlock.h>

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};

#endif /* _LINUX_WAIT_H */