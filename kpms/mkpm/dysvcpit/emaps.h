/* emaps.h - per-uid /proc/<pid>/maps 规则隐藏 (legacy)
 *
 * 跟 hide-so 干类似的事情, 但更细粒度: 支持按行匹配 (prefix/exact/regex),
 * 挂 getdents64 + seq_read 钩子, 让指定 uid 读 /proc/<pid>/maps 时
 * 看不到含特定 token 的行。
 *
 * 现在 hide-so 已经覆盖大部分场景, emaps 保留作为:
 *   - 旧测试 case 兼容性
 *   - 复杂 regex 匹配 (hide-so 不支持)
 *
 * 用法 (ctl0):
 *   emaps <uid> add <rule-string>
 *   emaps <uid> del <rule-string>
 *   emaps <uid> clear
 *   emaps <uid> list
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

struct seq_file;
int emaps_init();
void emaps_exit();
int emaps_main(struct opts *opts);
int emaps_test(struct opts *opts);
void emaps_patch_show(struct seq_file *m, size_t old);
