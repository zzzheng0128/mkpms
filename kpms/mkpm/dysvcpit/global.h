#ifndef GLOBALS_H
#define GLOBALS_H

#include <hook.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <ktypes.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <compiler.h>
#include <kpmodule.h>
#include <linux/llist.h>

#define ASHMEM_PREFIX "/dev/ashmem"

struct path
{
    struct vfsmount *mnt;
    struct dentry *dentry;
};


extern int target_uid;
extern u64 start_addr;
extern u64 end_addr;
extern int collect_svc;
extern int print_hook;
extern int uptime_offset;

extern u8 *sysctl_bootid;



extern long uptime;
extern unsigned long total_ram;
extern unsigned long free_ram;
extern unsigned long shared_ram;
extern unsigned long buffer_ram;
extern unsigned long total_swap;
extern unsigned long free_swap;
extern unsigned long total_high;
extern unsigned long free_high;

#endif