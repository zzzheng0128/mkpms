/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/anon_inodes.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

/* compat shim: KP header set 缺这个头, dysvcpit 需要 anon_inode_getfd 等
 * 来给 vm 注入创建匿名 inode。本文件只声明, 实现在内核里, KPM 通过
 * kallsyms_lookup_name 拿到函数地址调用。 */

#ifndef _LINUX_ANON_INODES_H
#define _LINUX_ANON_INODES_H

struct file_operations;

struct file *anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags);
int anon_inode_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags);

#endif /* _LINUX_ANON_INODES_H */


