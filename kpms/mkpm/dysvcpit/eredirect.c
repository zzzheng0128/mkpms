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

/* =====================================================================
 * eredirect.c - per-uid open/exec 路径重定向实现
 * =====================================================================
 *
 * 【核心思路】
 *   - 维护一个 rule list, 每个 rule: {from_path, to_path, uid}
 *   - 控制器通过 ctl0 ("eredirect <uid> add <from> <to>") 加规则
 *   - before-hook (openat/openat2): 命中 rule -> 把 path 参数改成 to_path,
 *     原 syscall 会打开 to 指向的真实文件 (通常是个我们预先准备好的 fake)
 *   - before-hook (execve): 命中 rule -> 把 filename 改成 to_path
 *
 * 【并发】
 *   与 ehide 一样: RCU 读 + spinlock 写, 老 node 用 call_rcu 延后释放。
 *
 * 【典型场景】
 *   - 反 frida 检测: 把目标对 /proc/<pid>/maps / /proc/<pid>/mem 的访问
 *     重定向到我们伪造的只读文件, 让目标看到假的内存布局
 *   - 反 qemu 检测: 把对 /dev/qemu_pipe 等设备路径的访问重定向到 /dev/null
 *
 * 【懒加载】 mkpm_call_dys 在首次 ctl0 "eredirect ..." 时调 eredirect_init。
 */
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "global.h"
#include "opts.h"
#include "eredirect.h"

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
static void (*kf__synchronize_rcu)(void);
static void (*kf_spin_unlock)(raw_spinlock_t *lock);
static void (*kf_spin_lock)(raw_spinlock_t *lock);
static int (*kf__kstrtoull)(const char *s, unsigned int base, unsigned long long *res);
static int (*kf__scnprintf)(char *buf, size_t size, const char *fmt, ...);
static void(*kf__putname)(struct filename *name);
static struct filename *(*kf__getname_kernel)(const char *);
static void *(*kf__memdup_user)(const void __user *, size_t);

static int  (*kf__kern_path)(const char *name, unsigned int flags, struct path *path);
static char *(*kf__d_path)(const struct path *path, char *buf, int buflen);
static void (*kf__path_put)(const struct path *path);

#define PATH_MAX 256
#define MAX_LINES 8
#define MAX_INPUT_SIZE 4096

enum redir_match_flags {
    REDIR_MATCH_PREFIX = 1 << 0,  // 前缀匹配
    REDIR_MATCH_EXACT  = 1 << 1,  // 精确匹配
};

struct so_range{
    char* name;
    u64 start;
    u64 end;
    struct list_head list;
    struct rcu_head rcu;
};

struct redir_rule {
    char   *from;
    size_t  from_len;
    char   *to;
    size_t  to_len;
    u32     flags;         // 前缀/精确
    u64     pc_begin;      // 可选：PC/LR 范围（包含）
    u64     pc_end;        // 可选：PC/LR 范围（包含）；都为0表示忽略地址限制
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

static LIST_HEAD(g_redir_rules);
static DEFINE_SPINLOCK(g_redir_lock);
static LIST_HEAD(g_ranges);
static DEFINE_SPINLOCK(g_ranges_lock);
static bool g_print_only = false; // 纯打印模式

typedef struct file *(*do_filp_open_func_t)(int dfd, struct filename *pathname, const struct open_flags *op);
static do_filp_open_func_t original_do_filp_open = NULL;
static do_filp_open_func_t backup_do_filp_open = NULL;
static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);

static bool hooked = false;

int r_target_uid = 0;
static bool is_uid()
{
     if (r_target_uid <= 0) return false;
    return current_uid() == r_target_uid;
}

static inline void set_priv_sel_allow(struct task_struct* task, int val){
    struct task_ext* ext = get_task_ext(task);
    if (likely(task_ext_valid(ext))){
        ext->priv_sel_allow = val;
        dsb(ish);
    }
}

static void free_range_rcu(struct rcu_head *rcu){
    struct so_range *r = container_of(rcu, struct so_range, rcu);
    if (r) {
        if (r->name) kf__kfree(r->name);
        kf__kfree(r);
    }
}

static int range_add_or_update(const char *name, u64 start, u64 end)
{
    if (!name || !*name) return -EINVAL;
    if (start && end && start > end) return -EINVAL;

    struct so_range *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    if (!nr) return -ENOMEM;
    memset(nr, 0, sizeof(*nr));
    nr->name = kf__kstrdup(name, GFP_KERNEL);
    if (!nr->name) { kf__kfree(nr); return -ENOMEM; }
    nr->start = start;
    nr->end   = end;

    kf_spin_lock(&g_ranges_lock);
    struct so_range *cur;
    list_for_each_entry(cur, &g_ranges, list) {
        if (!strcmp(cur->name, name)) {
            // replace
            nr->list = cur->list;
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&g_ranges_lock);
            kf__call_rcu(&cur->rcu, free_range_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &g_ranges);
    kf_spin_unlock(&g_ranges_lock);
    return 0;
}

static int range_del(const char *name)
{
    if (!name || !*name) return -EINVAL;
    kf_spin_lock(&g_ranges_lock);
    struct so_range *cur;
    list_for_each_entry(cur, &g_ranges, list) {
        if (!strcmp(cur->name, name)) {
            list_del_rcu(&cur->list);
            kf_spin_unlock(&g_ranges_lock);
            kf__call_rcu(&cur->rcu, free_range_rcu);
            return 0;
        }
    }
    kf_spin_unlock(&g_ranges_lock);
    return -ENOENT;
}

static void range_clear(void)
{
    kf_spin_lock(&g_ranges_lock);
    while (!list_empty(&g_ranges)) {
        struct so_range *cur = list_first_entry(&g_ranges, struct so_range, list);
        list_del_rcu(&cur->list);
        kf__call_rcu(&cur->rcu, free_range_rcu);
    }
    kf_spin_unlock(&g_ranges_lock);
}

static const struct so_range* range_find_by_pc(u64 pc)
{
    const struct so_range *hit = NULL;
    struct so_range *r;
    kf_rcu_read_lock();
    list_for_each_entry_rcu(r, &g_ranges, list) {
        if ((!r->start && !r->end) || (r->start <= pc && pc <= r->end)) {
            hit = r;
            break;
        }
    }
    kf_rcu_read_unlock();
    return hit;
}

static void free_rule_rcu(struct rcu_head *rcu)
{
    struct redir_rule *r = container_of(rcu, struct redir_rule, rcu);
    if (r) {
        kf__kfree(r->from);
        kf__kfree(r->to);
        kf__kfree(r);
    }
}

static int add_or_replace_rule(const char *from, const char *to, u32 flags, u64 pc_beg, u64 pc_end)
{
    if (!from || !*from || !to || !*to) return -EINVAL;
    if (!(flags & (REDIR_MATCH_PREFIX|REDIR_MATCH_EXACT))) return -EINVAL;

    struct redir_rule *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    if (!nr) return -ENOMEM;
    nr->from = kf__kstrdup(from, GFP_KERNEL);
    nr->to   = kf__kstrdup(to,   GFP_KERNEL);
    if (!nr->from || !nr->to) {
        kf__kfree(nr->from); 
        kf__kfree(nr->to); 
        kf__kfree(nr);
        return -ENOMEM;
    }
    nr->from_len = strlen(nr->from);
    nr->to_len   = strlen(nr->to);
    nr->flags    = flags;
    nr->pc_begin = pc_beg;
    nr->pc_end   = pc_end;

    kf_spin_lock(&g_redir_lock);
    struct redir_rule *cur;
    list_for_each_entry(cur, &g_redir_rules, list) {
        if (cur->from_len == nr->from_len && !memcmp(cur->from, nr->from, nr->from_len)) {
            // replace
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&g_redir_lock);
            kf__call_rcu(&cur->rcu, free_rule_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &g_redir_rules);
    kf_spin_unlock(&g_redir_lock);
    return 0;
}

static int del_rule(const char *from)
{
    if (!from || !*from) return -EINVAL;
    kf_spin_lock(&g_redir_lock);
    struct redir_rule *cur;
    list_for_each_entry(cur, &g_redir_rules, list) {
        if (!strcmp(cur->from, from)) {
            list_del_rcu(&cur->list);
            kf_spin_unlock(&g_redir_lock);
            kf__call_rcu(&cur->rcu, free_rule_rcu);
            return 0;
        }
    }
    kf_spin_unlock(&g_redir_lock);
    return -ENOENT;
}

static void clear_rules(void)
{
    kf_spin_lock(&g_redir_lock);
    while (!list_empty(&g_redir_rules)) {
        struct redir_rule *cur = list_first_entry(&g_redir_rules, struct redir_rule, list);
        list_del_rcu(&cur->list);
        kf__call_rcu(&cur->rcu, free_rule_rcu);
    }
    kf_spin_unlock(&g_redir_lock);
}

static bool pc_in_range(u64 pc, u64 beg, u64 end)
{
    if (!beg && !end) return true;           // 规则未限制 PC
    if (beg && end && beg <= pc && pc <= end) return true;
    return false;
}

static const struct redir_rule* match_rule_rcu(const char *path, u64 pc)
{
    const struct redir_rule *hit = NULL;
    kf_rcu_read_lock();
    struct redir_rule *r;
    list_for_each_entry_rcu(r, &g_redir_rules, list) {
        if (!pc_in_range(pc, r->pc_begin, r->pc_end))
            continue;
        if (r->flags & REDIR_MATCH_EXACT) {
            if (!strcmp(path, r->from)) { hit = r; break; }
        } else if (r->flags & REDIR_MATCH_PREFIX) {
            if (strncmp(path, r->from, r->from_len) == 0) { hit = r; break; }
        }
    }
    kf_rcu_read_unlock();
    return hit;
}
#define LOOKUP_FOLLOW 0x0001
static bool resolve_if_proc_fd(const char *in, char *out, size_t outsz)
{
    // 粗略匹配：/proc/<pid>/fd/<fd>
    if (!in || in[0] != '/') return false;
    if (strncmp(in, "/proc/", 6) != 0) return false;

    // 用 kern_path + d_path 跟随符号链接拿真实对象
    struct path p;
    if (!kf__kern_path || !kf__d_path || !kf__path_put) return false;
    if (kf__kern_path(in, LOOKUP_FOLLOW, &p) != 0) return false;

    char *s = kf__d_path(&p, out, outsz);
    kf__path_put(&p);
    if (IS_ERR(s)) return false;

    // d_path 可能返回在 out 内部偏移的指针，统一 memmove 到 out 起始
    if (s != out) {
        size_t n = strnlen(s, outsz-1);
        memmove(out, s, n);
        out[n] = '\0';
    }
    return true;
}


static __always_inline unsigned long io_untagged_addr(unsigned long addr)
{
    /* 顶字节掩码：0xFF << 56 */
    const unsigned long TOP_BYTE_MASK = (~0UL) << 56;   // = 0xFF00000000000000UL
    return addr & ~TOP_BYTE_MASK;
}


static u64 io_caller_pc(struct pt_regs *regs, u64 start){
    unsigned long elr = regs->user_regs.pc;
    unsigned long svcpc = elr - 4;
    unsigned long lr = regs->user_regs.regs[30];
    unsigned long callsite_doSyscall = lr - 4;
    unsigned long fp = regs->user_regs.regs[29];
    fp = io_untagged_addr(fp);
    unsigned long caller_lr = 0;
    const void __user *uaddr = (const void __user*)(fp+8);
    u64 *tmp = (u64 *)kf__memdup_user(uaddr,sizeof(u64));
    if (!IS_ERR(tmp)){
        caller_lr = (unsigned long)(*tmp);
        kf__kfree(tmp);
    }else{
        long err = PTR_ERR(tmp);
        // logkd("[io] caller_pc: memdup_user([fp+8]) failed: %ld (fp=0x%lx)\n", err, fp);
    }
    unsigned long callsite_vm_readv = caller_lr ? (caller_lr - start - 4) : 0; // 期望 0xA1114
    // logkd("[io] ELR=0x%lx SVC@0x%lx LR=0x%lx doSysBL@0x%lx prevLR=0x%lx prevBL@0x%lx\n",
    //          elr, svcpc, lr, callsite_doSyscall, caller_lr, callsite_vm_readv);
    return callsite_vm_readv;
}


// 声明：4.19 上 getname_kernel/putname 都在 <linux/namei.h>
static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
{
    // 先做一次最原始调用条件判断，尽量减小开销
    if (!is_uid())
        return backup_do_filp_open(dfd, pathname, op);

    struct task_struct *task = current;
    struct pt_regs *regs = _task_pt_reg(task);
    if (!regs)
        return backup_do_filp_open(dfd, pathname, op);

    // 你原本的“是否在某 so 的执行区间”判断
    u64 pc = regs->user_regs.pc;
    // if (!is_in_metasec(pc))
    //     return backup_do_filp_open(dfd, pathname, op);

    // `pathname->name` 是内核缓冲区里的 NUL 结尾字符串
    const char *orig = pathname && pathname->name ? pathname->name : NULL;
    if (!orig || !*orig)
        return backup_do_filp_open(dfd, pathname, op);
    if (strstr(orig, "cpag/prop.json") || strstr(orig, "cpag/prop2.json")){
        return backup_do_filp_open(dfd, pathname, op);
    }

    // 尝试解析 /proc/<pid>/fd/<n> 真实路径
    char realbuf[PATH_MAX];
    const char *path_for_print = orig;
    if (resolve_if_proc_fd(orig, realbuf, sizeof(realbuf))){
        path_for_print = realbuf;
    }    

    const struct so_range *hit = range_find_by_pc(pc);
    if (!hit){
        return backup_do_filp_open(dfd, pathname, op);
    }
    const char *so_name = hit ? hit->name : "unknown";
    u64 offset = hit ? (pc - hit->start) : pc;
    u64 caller_offset = io_caller_pc(regs,hit->start);
    if (g_print_only){
        // if (strstr(so_name, "libc.so")){
        //     return backup_do_filp_open(dfd, pathname, op);
        // }
        logkd("[IO] pc=0x%llx so=%s off=0x%llx offup=0x%llx path=%s", pc, so_name, offset, caller_offset,path_for_print);
        return backup_do_filp_open(dfd, pathname, op);
    }
    
    // 相对路径先不动，避免 dfd/cwd 差异；需要时再扩展
    if (orig[0] != '/')
        return backup_do_filp_open(dfd, pathname, op);

    // 查规则
    const struct redir_rule *rule = match_rule_rcu(orig, pc);
    if (!rule)
        return backup_do_filp_open(dfd, pathname, op);

    // 命中规则：构造新的 filename，直接传给备份函数
    // 注意：不用先打开原路径再 fput，避免多余开销 & 竞态
    struct filename *newname = kf__getname_kernel(rule->to);
    if (IS_ERR(newname)) {
        // 构造失败，回退到原始行为
        return backup_do_filp_open(dfd, pathname, op);
    }

    // 可选：白名单开关（你的 ext->priv_sel_allow）——如果底层有 LSM/selinux 绕行需求
    set_priv_sel_allow(current, true);
    struct file *filp = backup_do_filp_open(dfd, newname, op);
    set_priv_sel_allow(current, false);

    kf__putname(newname);

    // 打印一次日志方便核对
    if (!IS_ERR(filp)) {
        logkd("redirect: '%s' => '%s' (pc=0x%llx)", orig, rule->to, pc);
    } else {
        logkd("redirect FAIL: '%s' => '%s' (pc=0x%llx, err=%ld)", orig, rule->to, pc, PTR_ERR(filp));
    }
    return filp;
}

static inline bool hook_do_filp_open(){
    if (original_do_filp_open){
        hook_err_t hook_err = hook((void *)original_do_filp_open, (void *)replace_do_filp_open, (void **)&backup_do_filp_open);
        if (hook_err != HOOK_NO_ERR){
            hooked = false;
            logkd("redirect hook do_filp_open, %llx, error: %d", original_do_filp_open, hook_err);
        }else{
            hooked = true;
            return true;
        }
    }else{
        hooked = false;
        hook_err_t hook_err = HOOK_BAD_ADDRESS;
        logkd("%s","redirect no symbol: do_filp_open");
    }
    return false;
}

static inline bool install_hook(){
    bool ret = false;
    if (!hooked){
        if (hook_do_filp_open()){
            logkd("%s","redirect hook installed...");
            return true;
        }else{
            logkd("%s","redirect installation failed...");
        }
    }
    return ret;
}

static inline bool uninstall_hook(){
    if (hooked && original_do_filp_open){
        unhook((void *)original_do_filp_open);
        hooked = false;
        logkd("%s","hook uninstalled...");
    }
}

int eredirect_init(){
    spin_lock_init(&g_redir_lock);
    spin_lock_init(&g_ranges_lock);

    kf_rcu_read_lock = (void *)kallsyms_lookup_name("__rcu_read_lock");
    kf_rcu_read_unlock = (void *)kallsyms_lookup_name("__rcu_read_unlock");
    kf__call_rcu = (void *)kallsyms_lookup_name("call_rcu");
    kf__synchronize_rcu = (void *)kallsyms_lookup_name("synchronize_rcu");
    kf_spin_unlock = (void *)kallsyms_lookup_name("_raw_spin_unlock");
    kf_spin_lock = (void *)kallsyms_lookup_name("_raw_spin_lock");
    kf__kmalloc = (void *)kallsyms_lookup_name("__kmalloc");
    kf__kfree = (void*)kallsyms_lookup_name("kfree");
    kf__memset = (void*)kallsyms_lookup_name("memset");
    kf__kstrdup = (void*)kallsyms_lookup_name("kstrdup");
    kf_kstrtoint = (void*)kallsyms_lookup_name("kstrtoint");
    kf__kstrtoull = (void*)kallsyms_lookup_name("kstrtoull");
    kf__scnprintf = (void*)kallsyms_lookup_name("scnprintf");
    kf__putname = (void*)kallsyms_lookup_name("putname");
    kf__getname_kernel = (void*)kallsyms_lookup_name("getname_kernel");
    kf__kern_path = (void*)kallsyms_lookup_name("kern_path");
    kf__d_path = (void*)kallsyms_lookup_name("d_path");
    kf__path_put = (void*)kallsyms_lookup_name("path_put");
    kf__memdup_user = (void*)kallsyms_lookup_name("memdup_user");

    logkd("rcu_read_lock:%p", kf_rcu_read_lock);
    logkd("rcu_read_unlock:%p", kf_rcu_read_unlock);
    logkd("call_rcu:%p", kf__call_rcu);
    logkd("synchronize_rcu:%p", kf__synchronize_rcu);
    logkd("spin_unlock:%p", kf_spin_unlock);
    logkd("spin_lock:%p", kf_spin_lock);
    logkd("__kmalloc:%p", kf__kmalloc);
    logkd("kfree:%p", kf__kfree);
    logkd("memset:%p", kf__memset);
    logkd("kstrdup:%p", kf__kstrdup);
    logkd("kstrtoint:%p", kf_kstrtoint);
    logkd("kf__kstrtoull:%p", kf__kstrtoull);
    logkd("kf__scnprintf:%p", kf__scnprintf);
    logkd("kf__putname:%p", kf__putname);
    logkd("kf_getname_kernel:%p", kf__getname_kernel);
    logkd("kf__kern_path:%p", kf__kern_path);
    logkd("kf__d_path:%p", kf__d_path);
    logkd("kf__path_put:%p", kf__path_put);
    logkd("kf__memdup_user:%p", kf__memdup_user);

    original_do_filp_open = (do_filp_open_func_t)kallsyms_lookup_name("do_filp_open");
    logkd("redirect do_filp_open:%llx", original_do_filp_open);
    return 0;
}

/*
 * 读取 redirect 当前状态，供 mkpm 的 ctl0 返回给 kpctl。
 * eredirect_main() 为历史 ABI，只能返回 int；状态命令需要单独的文本
 * 快照，避免用户只能看到 "ok=0" 而不知道 hook 是否真的打开。
 */
int eredirect_status(char *out, int outlen)
{
    int rules = 0;
    int ranges = 0;
    struct redir_rule *rule;
    struct so_range *range;

    if (!out || outlen <= 0 || !kf__scnprintf)
        return -EINVAL;

    if (kf_spin_lock)
        kf_spin_lock(&g_redir_lock);
    list_for_each_entry(rule, &g_redir_rules, list)
        rules++;
    if (kf_spin_unlock)
        kf_spin_unlock(&g_redir_lock);

    if (kf_spin_lock)
        kf_spin_lock(&g_ranges_lock);
    list_for_each_entry(range, &g_ranges, list)
        ranges++;
    if (kf_spin_unlock)
        kf_spin_unlock(&g_ranges_lock);

    return kf__scnprintf(out, (size_t)outlen,
                         "redirect: hooked=%d uid=%d print=%d rules=%d ranges=%d\\n",
                         hooked ? 1 : 0, r_target_uid, g_print_only ? 1 : 0,
                         rules, ranges);
}

// 例如：redirect <uid> addprefix <from> <to> [pc_beg_hex] [pc_end_hex]
//     redirect <uid> addexact  <from> <to> [pc_beg_hex] [pc_end_hex]
//     redirect <uid> del       <from>
//     redirect <uid> clear
//     redirect <uid> print on / off;
//     redirect <uid> range add lib.so 0x1121121 0x1121212
//     redirect <uid> range del lib.so
//     redirect <uid> range clear
//     redirect <uid> range list    
int eredirect_main(struct opts *opts)
{
    int err = 0;
    if (opts->size < 3) return -EINVAL;

    err = kf_kstrtoint(opts->args[1], 10, &r_target_uid);
    if (err) r_target_uid = -1;

    if (!strcmp(opts->args[2], "print") && opts->size >= 4){
        g_print_only = !strcmp(opts->args[3], "on");
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
        clear_rules();
        return 0;
    }
    if (!strcmp(opts->args[2], "del") && opts->size >= 4) {
        return del_rule(opts->args[3]);
    }
    if ((!strcmp(opts->args[2], "addprefix") || !strcmp(opts->args[2], "addexact")) && opts->size >= 5) {
        const char *from = opts->args[3];
        const char *to   = opts->args[4];
        u32 flags = !strcmp(opts->args[2], "addprefix") ? REDIR_MATCH_PREFIX : REDIR_MATCH_EXACT;
        u64 beg = 0, end = 0;
        if (opts->size >= 5) kf__kstrtoull(opts->args[5], 16, &beg);
        if (opts->size >= 6) kf__kstrtoull(opts->args[6], 16, &end);
        return add_or_replace_rule(from, to, flags, beg, end);
    }

    if (!strcmp(opts->args[2], "range") && opts->size >= 4) {
        const char *sub = opts->args[3];

        if (!strcmp(sub, "add") && opts->size >= 7) {
            const char *name = opts->args[4];
            u64 beg = 0, end = 0;
            kf__kstrtoull(opts->args[5], 10, &beg);
            kf__kstrtoull(opts->args[6], 10, &end);
            return range_add_or_update(name, beg, end);
        }

        // eredirect <uid> range del <name>
        if (!strcmp(sub, "del") && opts->size >= 5) {
            return range_del(opts->args[4]);
        }

        // eredirect <uid> range clear
        if (!strcmp(sub, "clear")) {
            range_clear();
            return 0;
        }

        // eredirect <uid> range list
        if (!strcmp(sub, "list")) {
            int i = 0;
            kf_rcu_read_lock();
            struct so_range *r;
            list_for_each_entry_rcu(r, &g_ranges, list) {
                logkd("[CPAG] range#%d name=%s [0x%llx - 0x%llx]", i++, r->name, r->start, r->end);
            }
            kf_rcu_read_unlock();
            if (!i) logkd("[CPAG] no ranges");
            return 0;
        }
    }
    return -EINVAL;
}

void eredirect_exit()
{
    logkd("%s","eredirect_exit");
    uninstall_hook();
    clear_rules();
    range_clear();
    logkd("[CPAG] eredirect_exit");
}
