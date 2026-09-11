/* eredirect.h - per-uid open/exec 路径重定向
 *
 * 让指定 uid 的进程在 open()/execve() 时, 把对某个 path 的访问重定向
 * 到另一个 path (典型用途: 把 /proc/self/maps 重定向到伪造的 maps 文件,
 * 让反调试检测读不到真实内存布局)。
 *
 * 用法 (ctl0):
 *   eredirect <uid> add <from-path> <to-path>
 *   eredirect <uid> del <from-path>
 *   eredirect <uid> clear
 *   eredirect <uid> list
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

int eredirect_main(struct opts *opts);
/* 合并入口使用的状态快照；返回写入的字符数或负 errno。 */
int eredirect_status(char *out, int outlen);
void eredirect_exit();
int eredirect_init();
