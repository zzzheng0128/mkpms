/* ehide.h - per-uid readdir 入口隐藏
 *
 * 对指定 uid 的进程, hook getdents64 / faccessat 系列, 让它们看到的目录列表
 * 里不含匹配规则的文件 (前缀 / 精确 / tid)。规则存成链表, 通过 RCU 保护读写。
 *
 * 与 hide-so 的区别:
 *   - hide-so 隐藏的是 VMA (maps) 和 thread name, 是 hide-maps 模块
 *   - ehide 隐藏的是普通文件系统路径 (procfs / sysfs / 任意路径)
 *
 * 用法 (ctl0):
 *   ehide <uid> addprefix <path>
 *   ehide <uid> addexact <name>
 *   ehide <uid> addtid <pid>
 *   ehide <uid> del <path>
 *   ehide <uid> clear
 *   ehide <uid> range list|add <path>
 */
#include <ktypes.h>
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

int ehide_main(struct opts *opts);
void ehide_exit();
int ehide_init();