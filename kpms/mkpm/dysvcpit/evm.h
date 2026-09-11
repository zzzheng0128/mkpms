/* evm.h - per-uid 进程 vm read/dump 控制
 *
 * 对指定 uid 的进程, 控制它能不能读 /proc/<pid>/mem 和 /proc/<pid>/maps,
 * 或者返回伪造的 mem 数据。典型用途: 阻止反调试检测读我们的注入器进程
 * 的内存。
 *
 * 用法 (ctl0):
 *   evm <uid> block <pid>     - 阻止 uid 读 pid 的 mem
 *   evm <uid> unblock <pid>
 *   evm <uid> fake <pid>      - 返回伪造的 mem 数据 (占位)
 *   evm <uid> clear
 *   evm <uid> list
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

int evm_main(struct opts *opts);
void evm_exit();
int evm_init();