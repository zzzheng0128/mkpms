#ifndef _LINUX_POLL_H
/* compat shim: KP header set 缺 poll_table_struct 类型,
 * 一些内核头通过这个头间接引用。dysvcpit 没直接用 poll, 但保留以
 * 防依赖链断。 */
#define _LINUX_POLL_H

#include <linux/wait.h>

typedef struct wait_queue_head wait_queue_head_t;
struct poll_table_struct;
/* 
 * structures and helpers for f_op->poll implementations
 */
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

/*
 * Do not touch the structure directly, use the access functions
 * poll_does_not_wait() and poll_requested_events() instead.
 */
typedef struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
} poll_table;

#endif