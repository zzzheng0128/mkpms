#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <taskext.h>
#include <linux/llist.h>
#include <ktypes.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "global.h"
#include "opts.h"
#include "ehide.h"

/* =====================================================================
 * ehide.c - per-uid readdir 入口隐藏实现
 * =====================================================================
 *
 * 【核心思路】
 *   - 维护一个 rule list, 每个 rule: {prefix | exact | tid} + path
 *   - 规则挂在 uid 下, 每个 uid 一个链表头
 *   - 控制器通过 ctl0 ("ehide <uid> addprefix|addexact|addtid ...") 加 / 删
 *   - before-hook (faccessat 系): 命中 -> 强制 -ENOENT
 *   - after-hook (getdents64): 命中 -> 过滤掉目录条目 (类似 antidetect)
 *
 * 【并发】
 *   - 读路径 (syscall 上下文): RCU 读锁保护 list 遍历
 *   - 写路径 (ctl0 上下文): spin_lock + 改 list, 最后 synchronize_rcu
 *     再释放被替换的 node (call_rcu)
 *
 * 【依赖】
 *   - global.h 提供 ASHMEM_PREFIX 等常量和全局变量
 *   - opts.h 提供 getopt 解析
 *   - 懒加载: 由 mkpm_call_dys 在首次 ctl0 "ehide ..." 时调 ehide_init
 */

#define __GFP_DIRECT_RECLAIM 0x400u
#define __GFP_KSWAPD_RECLAIM 0x800u
#define __GFP_ATOMIC 0x200u
#define __GFP_HIGH 0x20u
#define __GFP_IO 0x40u
#define __GFP_FS 0x80u
#define __GFP_RECLAIM ((__force gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))
#define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

static void *(*kf__kmalloc)(size_t size, gfp_t flags);
static void (*kf__kfree)(const void *);
static void *(*kf__memset)(void *b, int c, size_t len);
static char *(*kf__kstrdup)(const char *s, gfp_t gfp);
static int (*kf_kstrtoint)(const char *s, unsigned int base, int *res);
static void (*kf_rcu_read_lock)(void);
static void (*kf_rcu_read_unlock)(void);
static void (*kf__call_rcu)(struct rcu_head *head, rcu_callback_t func);
static void (*kf_spin_unlock)(raw_spinlock_t *lock);
static void (*kf_spin_lock)(raw_spinlock_t *lock);
static int (*kf__kstrtoull)(const char *s, unsigned int base, unsigned long long *res);
static int (*kf__scnprintf)(char *buf, size_t size, const char *fmt, ...);

#define PATH_MAX 256
#define MAX_LINES 8
#define MAX_INPUT_SIZE 4096

enum hide_match_flags {
    HIDE_MATCH_PREFIX = 1 << 0,  // 前缀匹配
    HIDE_MATCH_EXACT  = 1 << 1,  // 精确匹配
    HIDE_MATCH_TID    = 1 << 2,  // 匹配/proc/self/task/tid
};

struct hide_so_range{
    char* name;
    u64 start;
    u64 end;
    struct list_head list;
    struct rcu_head rcu;
};

struct hide_rule {
    char   *match;
    size_t  match_len;
    u32     flags;         // 前缀/精确
    struct list_head list;
    struct rcu_head   rcu;
};

struct file {
    union {
        struct llist_node    fu_llist;
        struct rcu_head      fu_rcuhead;
    } f_u;
    struct path     f_path;
    struct inode    *f_inode;
};

struct open_flags {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

static LIST_HEAD(g_hide_rules);
static DEFINE_SPINLOCK(g_hide_lock);
static LIST_HEAD(g_hide_ranges);
static DEFINE_SPINLOCK(g_hide_ranges_lock);
static bool g_hide_print_only = false; // 纯打印模式


typedef int (*filldir64_func_t)(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type);
static filldir64_func_t origin_filldir64 = NULL;
static filldir64_func_t backup_filldir64 = NULL;         

static bool hide_hooked = false;

int r_hide_target_uid = 0;
static bool is_hide_uid()
{
     if (r_hide_target_uid <= 0) return false;
    return current_uid() == r_hide_target_uid;
}


static void free_hide_range_rcu(struct rcu_head *rcu){
    struct hide_so_range *r = container_of(rcu, struct hide_so_range, rcu);
    if (r) {
        if (r->name) kf__kfree(r->name);
        kf__kfree(r);
    }
}

static int hide_range_add_or_update(const char *name, u64 start, u64 end)
{
    if (!name || !*name) return -EINVAL;
    if (start && end && start > end) return -EINVAL;

    struct hide_so_range *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    if (!nr) return -ENOMEM;
    memset(nr, 0, sizeof(*nr));
    nr->name = kf__kstrdup(name, GFP_KERNEL);
    if (!nr->name) { kf__kfree(nr); return -ENOMEM; }
    nr->start = start;
    nr->end   = end;

    kf_spin_lock(&g_hide_ranges_lock);
    struct hide_so_range *cur;
    list_for_each_entry(cur, &g_hide_ranges, list) {
        if (!strcmp(cur->name, name)) {
            // replace
            nr->list = cur->list;
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&g_hide_ranges_lock);
            kf__call_rcu(&cur->rcu, free_hide_range_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &g_hide_ranges);
    kf_spin_unlock(&g_hide_ranges_lock);
    return 0;
}

static int hide_range_del(const char *name)
{
    if (!name || !*name) return -EINVAL;
    kf_spin_lock(&g_hide_ranges_lock);
    struct hide_so_range *cur;
    list_for_each_entry(cur, &g_hide_ranges, list) {
        if (!strcmp(cur->name, name)) {
            list_del_rcu(&cur->list);
            kf_spin_unlock(&g_hide_ranges_lock);
            kf__call_rcu(&cur->rcu, free_hide_range_rcu);
            return 0;
        }
    }
    kf_spin_unlock(&g_hide_ranges_lock);
    return -ENOENT;
}

static void hide_range_clear(void)
{
    kf_spin_lock(&g_hide_ranges_lock);
    while (!list_empty(&g_hide_ranges)) {
        struct hide_so_range *cur = list_first_entry(&g_hide_ranges, struct hide_so_range, list);
        list_del_rcu(&cur->list);
        kf__call_rcu(&cur->rcu, free_hide_range_rcu);
    }
    kf_spin_unlock(&g_hide_ranges_lock);
}

static const struct hide_so_range* hide_range_find_by_pc(u64 pc)
{
    const struct hide_so_range *hit = NULL;
    struct hide_so_range *r;
    kf_rcu_read_lock();
    list_for_each_entry_rcu(r, &g_hide_ranges, list) {
        if ((!r->start && !r->end) || (r->start <= pc && pc <= r->end)) {
            hit = r;
            break;
        }
    }
    kf_rcu_read_unlock();
    return hit;
}

static void hide_free_rule_rcu(struct rcu_head *rcu)
{
    struct hide_rule *r = container_of(rcu, struct hide_rule, rcu);
    if (r) {
        kf__kfree(r->match);
        kf__kfree(r);
    }
}

static int hide_add_or_replace_rule(const char *match, u32 flags)
{
    if (!match || !*match ) return -EINVAL;
    if (!(flags & (HIDE_MATCH_PREFIX|HIDE_MATCH_EXACT|HIDE_MATCH_TID))) return -EINVAL;

    struct hide_rule *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    if (!nr) return -ENOMEM;
    nr->match = kf__kstrdup(match, GFP_KERNEL);
    if (!nr->match) {
        kf__kfree(nr->match); 
        return -ENOMEM;
    }
    nr->match_len = strlen(nr->match);
    nr->flags    = flags;

    kf_spin_lock(&g_hide_lock);
    struct hide_rule *cur;
    list_for_each_entry(cur, &g_hide_rules, list) {
        if (cur->match_len == nr->match_len && !memcmp(cur->match, nr->match, nr->match_len)) {
            // replace
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&g_hide_lock);
            kf__call_rcu(&cur->rcu, hide_free_rule_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &g_hide_rules);
    kf_spin_unlock(&g_hide_lock);
    return 0;
}

static int hide_del_rule(const char *match)
{
    if (!match || !*match) return -EINVAL;
    kf_spin_lock(&g_hide_lock);
    struct hide_rule *cur;
    list_for_each_entry(cur, &g_hide_rules, list) {
        if (!strcmp(cur->match, match)) {
            list_del_rcu(&cur->list);
            kf_spin_unlock(&g_hide_lock);
            kf__call_rcu(&cur->rcu, hide_free_rule_rcu);
            return 0;
        }
    }
    kf_spin_unlock(&g_hide_lock);
    return -ENOENT;
}

static void hide_clear_rules(void)
{
    kf_spin_lock(&g_hide_lock);
    while (!list_empty(&g_hide_rules)) {
        struct hide_rule *cur = list_first_entry(&g_hide_rules, struct hide_rule, list);
        list_del_rcu(&cur->list);
        kf__call_rcu(&cur->rcu, hide_free_rule_rcu);
    }
    kf_spin_unlock(&g_hide_lock);
}

static bool hide_pc_in_range(u64 pc, u64 beg, u64 end)
{
    if (!beg && !end) return true;           // 规则未限制 PC
    if (beg && end && beg <= pc && pc <= end) return true;
    return false;
}

static const struct hide_rule* hide_match_rule_rcu(const char *path, u64 pc)
{
    const struct hide_rule *hit = NULL;
    kf_rcu_read_lock();
    struct hide_rule *r;
    list_for_each_entry_rcu(r, &g_hide_rules, list) {
        if (r->flags & HIDE_MATCH_EXACT) {
            if (!strcmp(path, r->match)) { hit = r; break; }
        } else if (r->flags & HIDE_MATCH_PREFIX) {
            if (strncmp(path, r->match, r->match_len) == 0) { hit = r; break; }
        }
    }
    kf_rcu_read_unlock();
    return hit;
}

static int replace_filldir64(struct dir_context *ctx, const char *name, int namelen,
             loff_t offset, u64 ino, unsigned int d_type)
{
    // 先做一次最原始调用条件判断，尽量减小开销
    if (!is_hide_uid())
        return backup_filldir64(ctx, name, namelen, offset, ino, d_type);

    struct task_struct *task = current;
    struct pt_regs *regs = _task_pt_reg(task);
    if (!regs)
        return backup_filldir64(ctx, name, namelen, offset, ino, d_type);

    char buf[PATH_MAX] = {0};
    if (namelen >= PATH_MAX) 
        return backup_filldir64(ctx, name, namelen, offset, ino, d_type);

    memcpy(buf, name, namelen);
    buf[namelen] = '\0';

    const struct hide_rule *r;
    kf_rcu_read_lock();
    list_for_each_entry_rcu(r, &g_hide_rules, list) {
        if (r->flags & HIDE_MATCH_EXACT) {
            if (strcmp(buf, r->match) == 0) {
                logkd("hide exact:%s", buf);
                kf_rcu_read_unlock();
                return 0;
            }
        } else if (r->flags & HIDE_MATCH_PREFIX) {
            if (strncmp(buf, r->match, r->match_len) == 0) {
                logkd("hide prefix:%s", buf);
                kf_rcu_read_unlock();
                return 0;
            }
        } else if (r->flags & HIDE_MATCH_TID) {
            int tid = 0;
            int match_tid = 0;
            if (kf_kstrtoint(buf, 10, &tid) == 0 && kf_kstrtoint(r->match, 10, &match_tid) == 0 && tid == match_tid) {
                logkd("hide tid:%d", tid);
                kf_rcu_read_unlock();
                return 0;
            }
        }
    }
    kf_rcu_read_unlock();

    return backup_filldir64(ctx, name, namelen, offset, ino, d_type);
}

static inline bool hook_filldir64(){
    if (origin_filldir64){
        hook_err_t hook_err = hook((void *)origin_filldir64, (void *)replace_filldir64, (void **)&backup_filldir64);
        if (hook_err != HOOK_NO_ERR){
            hide_hooked = false;
            logkd("hide hook filldir64, %llx, error: %d", origin_filldir64, hook_err);
        }else{
            hide_hooked = true;
            return true;
        }
    }else{
        hide_hooked = false;
        hook_err_t hook_err = HOOK_BAD_ADDRESS;
        logkd("%s","hide no symbol: filldir64");
    }
    return false;
}

static inline bool install_hook(){
    bool ret = false;
    if (!hide_hooked){
        if (hook_filldir64()){
            logkd("%s","hide hook installed...");
            return true;
        }else{
            logkd("%s","hide installation failed...");
        }
    }
    return ret;
}

static inline bool uninstall_hook(){
    if (hide_hooked && origin_filldir64){
        unhook((void *)origin_filldir64);
        hide_hooked = false;
        logkd("%s","hook uninstalled...");
    }
}

int ehide_init(){
    spin_lock_init(&g_hide_lock);
    spin_lock_init(&g_hide_ranges_lock);

    kf_rcu_read_lock = (void *)kallsyms_lookup_name("__rcu_read_lock");
    kf_rcu_read_unlock = (void *)kallsyms_lookup_name("__rcu_read_unlock");
    kf__call_rcu = (void *)kallsyms_lookup_name("call_rcu");
    kf_spin_unlock = (void *)kallsyms_lookup_name("_raw_spin_unlock");
    kf_spin_lock = (void *)kallsyms_lookup_name("_raw_spin_lock");
    kf__kmalloc = (void *)kallsyms_lookup_name("__kmalloc");
    kf__kfree = (void*)kallsyms_lookup_name("kfree");
    kf__memset = (void*)kallsyms_lookup_name("memset");
    kf__kstrdup = (void*)kallsyms_lookup_name("kstrdup");
    kf_kstrtoint = (void*)kallsyms_lookup_name("kstrtoint");
    kf__kstrtoull = (void*)kallsyms_lookup_name("kstrtoull");
    kf__scnprintf = (void*)kallsyms_lookup_name("scnprintf");

    logkd("rcu_read_lock:%p", kf_rcu_read_lock);
    logkd("rcu_read_unlock:%p", kf_rcu_read_unlock);
    logkd("call_rcu:%p", kf__call_rcu);
    logkd("spin_unlock:%p", kf_spin_unlock);
    logkd("spin_lock:%p", kf_spin_lock);
    logkd("__kmalloc:%p", kf__kmalloc);
    logkd("kfree:%p", kf__kfree);
    logkd("memset:%p", kf__memset);
    logkd("kstrdup:%p", kf__kstrdup);
    logkd("kstrtoint:%p", kf_kstrtoint);
    logkd("kf__kstrtoull:%p", kf__kstrtoull);
    logkd("kf__scnprintf:%p", kf__scnprintf);

    origin_filldir64 = (filldir64_func_t)kallsyms_lookup_name("filldir64");
    logkd("hide filldir64:%llx", origin_filldir64);
    return 0;
}

// 例如：ehide <uid> addprefix match 
//     ehide <uid> addexact  match
//.    ehide <uid> addtid.   tid
//     ehide <uid> del       match
//     ehide <uid> clear
//     ehide <uid> print on / off;
//     ehide <uid> range add lib.so 0x1121121 0x1121212
//     ehide <uid> range del lib.so
//     ehide <uid> range clear
//     ehide <uid> range list    
int ehide_main(struct opts *opts)
{
    int err = 0;
    if (opts->size < 3) return -EINVAL;

    err = kf_kstrtoint(opts->args[1], 10, &r_hide_target_uid);
    if (err) r_hide_target_uid = -1;

    if (!strcmp(opts->args[2], "print") && opts->size >= 4){
        g_hide_print_only = !strcmp(opts->args[3], "on");
        return 0;
    }

    if (!strcmp(opts->args[2], "hook")) {
        uninstall_hook();
        return install_hook() ? 0 : -EINVAL;
    }
    if (!strcmp(opts->args[2], "unhook")) {
        uninstall_hook();
        return 0;
    }
    if (!strcmp(opts->args[2], "clear")) {
        hide_clear_rules();
        return 0;
    }
    if (!strcmp(opts->args[2], "del") && opts->size >= 4) {
        return hide_del_rule(opts->args[3]);
    }
    if ((!strcmp(opts->args[2], "addprefix") 
        || !strcmp(opts->args[2], "addexact")
        || !strcmp(opts->args[2], "addtid")) && opts->size >= 3) {
        const char *match = opts->args[3];
        u32 flags = !strcmp(opts->args[2], "addexact") ? HIDE_MATCH_EXACT : (!strcmp(opts->args[2], "addprefix") ? HIDE_MATCH_PREFIX : HIDE_MATCH_TID);
        return hide_add_or_replace_rule(match, flags);
    }

    if (!strcmp(opts->args[2], "range") && opts->size >= 4) {
        const char *sub = opts->args[3];

        if (!strcmp(sub, "add") && opts->size >= 7) {
            const char *name = opts->args[4];
            u64 beg = 0, end = 0;
            kf__kstrtoull(opts->args[5], 10, &beg);
            kf__kstrtoull(opts->args[6], 10, &end);
            return hide_range_add_or_update(name, beg, end);
        }

        // ehide <uid> range del <name>
        if (!strcmp(sub, "del") && opts->size >= 5) {
            return hide_range_del(opts->args[4]);
        }

        // ehide <uid> range clear
        if (!strcmp(sub, "clear")) {
            hide_range_clear();
            return 0;
        }

        // ehide <uid> range list
        if (!strcmp(sub, "list")) {
            int i = 0;
            kf_rcu_read_lock();
            struct hide_so_range *r;
            list_for_each_entry_rcu(r, &g_hide_ranges, list) {
                logkd("[CPAG] range#%d name=%s [0x%llx - 0x%llx]", i++, r->name, r->start, r->end);
            }
            kf_rcu_read_unlock();
            if (!i) logkd("[CPAG] no ranges");
            return 0;
        }
    }
    return -EINVAL;
}

void ehide_exit()
{
    logkd("%s","ehide_exit");
    uninstall_hook();
    hide_clear_rules();
    hide_range_clear();
    logkd("[CPAG] ehide_exit");
}