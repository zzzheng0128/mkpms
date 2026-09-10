#ifndef _LINUX_POLL_H
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