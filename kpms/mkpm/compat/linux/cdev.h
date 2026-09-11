/* SPDX-License-Identifier: GPL-2.0 */
/* compat shim: KP header set 缺 char device 注册 API (cdev_*)。
 * dysvcpit 没用上 cdev (我们不导出字符设备), 这里只是把声明补齐,
 * 防止依赖 cdev 的内核代码头文件路径走不通。 */
#ifndef _LINUX_CDEV_H
#define _LINUX_CDEV_H

#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/device.h>

struct file_operations;
struct inode;
struct module;
struct cdev;
// struct cdev {
// 	struct kobject kobj;
// 	struct module *owner;
// 	const struct file_operations *ops;
// 	struct list_head list;
// 	dev_t dev;
// 	unsigned int count;
// } __randomize_layout;

void cdev_init(struct cdev *, const struct file_operations *);

struct cdev *cdev_alloc(void);

void cdev_put(struct cdev *p);

int cdev_add(struct cdev *, dev_t, unsigned);

void cdev_set_parent(struct cdev *p, struct kobject *kobj);
int cdev_device_add(struct cdev *cdev, struct device *dev);
void cdev_device_del(struct cdev *cdev, struct device *dev);

void cdev_del(struct cdev *);

void cd_forget(struct inode *);

#endif