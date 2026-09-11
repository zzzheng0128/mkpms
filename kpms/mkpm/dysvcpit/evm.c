// evm.c - full file (RCU + list_head pending fput, raw spinlock, no workqueue)

/* =====================================================================
 * evm.c - per-uid /proc/<pid>/mem 访问控制
 * =====================================================================
 *
 * 【核心思路】
 *   - 维护一个 rule list: {caller_uid, target_tgid, mode: block|allow|fake}
 *   - before-hook (process_vm_readv / ptrace / read(mem fd)):
 *     命中 rule -> 按 mode 决定: block 直接 -EPERM, fake 返回全 0
 *
 * 【实现细节】
 *   - 用 RCU + list_head 保护 rule 链表
 *   - 待释放的 file 指针挂 pending list, 在 synchronize_rcu 后调 fput
 *   - 不用 workqueue, 减少攻击面
 *
 * 【典型用途】
 *   - 阻止目标读我们的注入器进程 / frida-agent 的内存布局
 *   - 给反调试检测返回伪造的 mem, 让它以为我们在调试别的进程
 *
 * 【懒加载】 mkpm_call_dys 在首次 ctl0 "evm ..." 时调 evm_init。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <asm/processor.h> /* _task_pt_reg() declaration (KP tree) */
#include <taskext.h>
#include <ktypes.h>
#include <baselib.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <uapi/linux/limits.h>
#include "global.h"
#include "opts.h"
#include "evm.h"

#define __GFP_DIRECT_RECLAIM 0x400u
#define __GFP_KSWAPD_RECLAIM 0x800u
#define __GFP_ATOMIC 0x200u
#define __GFP_HIGH 0x20u
#define __GFP_IO 0x40u
#define __GFP_FS 0x80u
#define __GFP_RECLAIM ((__force gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))
#define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

typedef __s64 time64_t;
struct timespec64 { time64_t tv_sec; long int tv_nsec; };

struct iovec { void __user * iov_base; unsigned long iov_len; };

/* 注意：仅用到极少字段，避免强耦合 */
struct file {
    union {
        struct rcu_head      fu_rcuhead;
    } f_u;
    struct path     f_path;
    struct inode    *f_inode;
};

static void *(*kd__kmalloc)(size_t size, gfp_t flags);
static void (*kd__kfree)(const void *);
static void *(*kd___memset)(void *b, int c, size_t len);
static char *(*kd__kstrdup)(const char *s, gfp_t gfp);
static int (*kd_kstrtoint)(const char *s, unsigned int base, int *res);
static void (*kd_rcu_read_lock)(void);
static void (*kd_rcu_read_unlock)(void);
static void (*kd__call_rcu)(struct rcu_head *head, rcu_callback_t func);
static int (*kd__kstrtoull)(const char *s, unsigned int base, unsigned long long *res);
static int (*kd__scnprintf)(char *buf, size_t size, const char *fmt, ...);
static void (*kd__down_read)(struct rw_semaphore *sem);
static void (*kd__up_read)(struct rw_semaphore *sem);
static struct pid *(*kd__find_vpid)(int nr);
static struct task_struct *(*kd__pid_task)(struct pid *pid, enum pid_type);
static struct mm_struct *(*kd__get_task_mm)(struct task_struct *task);
static void (*kd____put_task_struct)(struct task_struct *t);
static struct vm_area_struct *(*kd_find_vma)(struct mm_struct * mm, unsigned long addr);
static void (*kd__mmput)(struct mm_struct *);
static size_t (*kd____strlcpy)(char *dest, const char *src, size_t size);
static int  (*kd__kern_path)(const char *name, unsigned int flags, struct path *path);
static char *(*kd__d_path)(const struct path *path, char *buf, int buflen);
static void (*kd__path_put)(const struct path *path);
static void *(*kd__memdup_user)(const void __user *, size_t);
static struct task_struct *(*kd__find_task_by_vpid)(pid_t nr);
static int (*kd__down_read_trylock)(struct rw_semaphore *sem);
static int (*kd__access_process_vm)(struct task_struct *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags);
static const char * (*kd__arch_vma_name)(struct vm_area_struct *vma);
static int (*kd__sscanf)(const char *buf, const char *fmt, ...);
static void (*kd___ktime_get_real_ts64)(struct timespec64 *tv);
static struct file *(*kd___filp_open)(const char *, int, umode_t);
static ssize_t (*kd___kernel_write)(struct file *, const void *, size_t, loff_t *);
static int (*kd___filp_close)(struct file *, fl_owner_t id);
static struct file *(*kd___fget)(unsigned int fd);
static void (*kd___fput)(struct file *file);

/* 原始自旋锁函数指针（与 raw_spinlock_t 类型匹配） */
static unsigned long (*kd___raw_spin_lock_irqsave)(raw_spinlock_t *lock);
static void (*kd___raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags);

/* ===== 偏移/布局（基于你当前内核版本） ===== */
#define MM_OFF_MMAP_SEM 0x60
#define VMA_OFF_START 0x00
#define VMA_OFF_END   0x08
#define VMA_OFF_FILE  0xa0
#define VMA_OFF_PGOFF 0x98
#define VMA_OFF_ANON_NAME 0x58
#define VMA_OFF_FLAGS 0x50

#ifndef PAGE_SHIFT
# define PAGE_SHIFT 12
#endif

static inline struct rw_semaphore *mm_mmap_sem_ptr(struct mm_struct *mm){ return (struct rw_semaphore *)((char *)mm + MM_OFF_MMAP_SEM); }
static inline unsigned long vma_start_val(void *vma){ return READ_ONCE(*(unsigned long *)((char *)vma + VMA_OFF_START)); }
static inline unsigned long vma_end_val(void *vma){ return READ_ONCE(*(unsigned long *)((char *)vma + VMA_OFF_END)); }
static inline struct file *vma_file_ptr(void *vma_base){ return READ_ONCE(*(struct file **)((char *)vma_base + VMA_OFF_FILE)); }
static inline unsigned long vma_pgoff_val(void *vma_base){ return READ_ONCE(*(unsigned long *)((char *)vma_base + VMA_OFF_PGOFF)); }
static inline const char __user *vma_anon_name_ptr(void *vma){ return READ_ONCE(*(const char __user **)((char *)vma + VMA_OFF_ANON_NAME)); }
static inline unsigned long vma_flags_val(void *vma){ return READ_ONCE(*(unsigned long *)((char *)vma + VMA_OFF_FLAGS)); }

static inline void vm_flags_to_perm(unsigned long flags, char perm[5]){
    perm[0] = (flags & 0x1) ? 'r' : '-';
    perm[1] = (flags & 0x2) ? 'w' : '-';
    perm[2] = (flags & 0x4) ? 'x' : '-';
    perm[3] = (flags & 0x8) ? 's' : 'p';
    perm[4] = '\0';
}

/* ===== hexdump/路径 常量 ===== */
#define VM_MAX_DUMP_PER_IOV   64
#define VM_MAX_DUMP_TOTAL     512
#define VM_PATH_BUF           512
#define VM_HEX_READ_CHUNK     512u
#define VM_DUMP_PATH_MAX      512

static char g_vm_dump_dir[VM_DUMP_PATH_MAX]; // 可选的“路径写”备选

/* ===== 统一 FD 目标（优先） ===== */
static int g_dump_fdno = -1;
static struct file *g_dump_file;           /* 持有一个有效引用（来自 fget） */
static DEFINE_SPINLOCK(g_dump_lock);

/* ===== 延后 fput：RCU + list_head ===== */
struct dump_rcu {
    struct rcu_head rcu;
    struct list_head list;
    struct file *f;
};
static LIST_HEAD(g_pending_fput);
static DEFINE_SPINLOCK(g_pending_fput_lock);

/* 把 RCU 回调给的旧 file* 放入挂起链表，稍后由安全点 drain */
static void dump_fput_rcu(struct rcu_head *rcu)
{
    struct dump_rcu *n = container_of(rcu, struct dump_rcu, rcu);
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_pending_fput_lock);
    list_add_tail_rcu(&n->list, &g_pending_fput);
    kd___raw_spin_unlock_irqrestore(&g_pending_fput_lock, flags);
}

/* 在进程上下文的安全点释放挂起 file*（写日志前、清理时、模块退出等调用） */
static void dump_fput_drain_list(void)
{
    LIST_HEAD(local);
    struct dump_rcu *n, *tmp;

    /* 快速搬空队列，降低锁持有时间 */
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_pending_fput_lock);
    list_splice_init(&g_pending_fput, &local);
    kd___raw_spin_unlock_irqrestore(&g_pending_fput_lock, flags);

    /* 逐个 fput 并释放节点 */
    list_for_each_entry_safe(n, tmp, &local, list) {
        kd___fput(n->f);
        kd__kfree(n);
    }
}

/* ===== 其它状态 ===== */
static LIST_HEAD(g_vm_repl_rules);
static DEFINE_SPINLOCK(g_vm_repl_lock);
static LIST_HEAD(g_vm_ranges);
static DEFINE_SPINLOCK(g_vm_ranges_lock);
static bool g_vm_print_only = false;

typedef int rwf_t;
typedef ssize_t (*process_vm_rw_func_t)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt,
                    const struct iovec __user *rvce, unsigned long riovcnt, unsigned long flags, int vm_write);
static process_vm_rw_func_t origin_process_vm_rw = NULL;
static process_vm_rw_func_t backup_process_vm_rw = NULL;

static bool vm_hooked = false;
int r_vm_target_uid = 0;
static bool is_vm_uid(){ if (r_vm_target_uid <= 0) return false; return current_uid() == r_vm_target_uid; }

/* ---------- 路径构造（作为 FD 不存在时的备选） ---------- */
static int vm_build_unified_path(char *out, size_t cap){
    if (!g_vm_dump_dir[0] || cap < 32) return -EINVAL;
    return kd__scnprintf(out, cap, "%s/vm_%d_kernel_log", g_vm_dump_dir, r_vm_target_uid);
}

/* ---------- 通过路径写（备选） ---------- */
static int vm_append_line_to_unified_file_path(const char *line){
    if (!line || !*line || !g_vm_dump_dir[0]) return -EINVAL;

    char path[VM_DUMP_PATH_MAX + 64];
    int n = vm_build_unified_path(path, sizeof(path));
    if (n <= 0) return -EINVAL;

    struct timespec64 ts;
    kd___ktime_get_real_ts64(&ts);
    unsigned long long sec  = (unsigned long long)ts.tv_sec;
    unsigned long usec = (unsigned long)(ts.tv_nsec / 1000);

    char buf[1600];
    int hdr = kd__scnprintf(buf, sizeof(buf), "[ %llu.%06lu ] %s\n", sec, usec, line);
    if (hdr <= 0) return -EINVAL;

    struct file *filp = kd___filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(filp)) {
        logkd("[vm] kernel_write open %s fail", path);
        return PTR_ERR(filp);
    }
    loff_t pos = 0;
    ssize_t wr = kd___kernel_write(filp, buf, hdr, &pos);
    if (wr < 0) logkd("[vm] kernel_write header failed: %zd", wr);
    kd___filp_close(filp, NULL);
    return 0;
}

static int vm_clear_unified_file(void){
    if (!g_vm_dump_dir[0]) return -EINVAL;
    char path[VM_DUMP_PATH_MAX + 64];
    int n = vm_build_unified_path(path, sizeof(path));
    if (n <= 0) return -EINVAL;

    struct file *filp = kd___filp_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(filp)) return PTR_ERR(filp);
    kd___filp_close(filp, NULL);
    return 0;
}

/* ---------- FD 设置/关闭（RCU 延后释放） ---------- */
static int vm_set_dump_fd(int fd)
{
    if (fd < 0) return -EINVAL;

    unsigned long flags = kd___raw_spin_lock_irqsave(&g_dump_lock);
    g_dump_fdno = fd;                  /* 交换 */
    kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);

    logkd("[vm] dump fd recorded: %d", fd);
    return 0;
}

static void vm_clear_dump_fd(void)
{
    struct file *old = NULL;

    unsigned long flags = kd___raw_spin_lock_irqsave(&g_dump_lock);
    g_dump_fdno = -1;
    old = g_dump_file;
    g_dump_file = NULL;
    kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);

    if (old) {
        struct dump_rcu *n = kd__kmalloc(sizeof(*n), GFP_KERNEL);
        if (!n) {
            kd___fput(old);
        } else {
            INIT_LIST_HEAD(&n->list);
            n->f = old;
            kd__call_rcu(&n->rcu, dump_fput_rcu);
        }
    }
}

/* 仅在目标进程上下文里调用：若尚未持有 file*，尝试从 g_dump_fdno 解析并安装 */
static void vm_maybe_resolve_dump_file(void)
{
    struct file *newf = NULL, *old = NULL;
    unsigned long flags;

    /* 快速判断：没有 fd 号就不做事 */
    if (g_dump_fdno < 0)
        return;

    /* 若已经有 file* 了，也不做事（避免重复 fget） */
    flags = kd___raw_spin_lock_irqsave(&g_dump_lock);
    if (g_dump_file) {
        kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);
        return;
    }
    kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);

    /* 在目标进程上下文里 fget(fd) —— 可能睡眠，但我们处于进程上下文是安全的 */
    newf = kd___fget(g_dump_fdno);
    if (!newf)
        return;

    /* 安装：与旧指针交换，并把旧的延后 fput（RCU+llist） */
    flags = kd___raw_spin_lock_irqsave(&g_dump_lock);
    old = g_dump_file;
    g_dump_file = newf;
    kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);

    if (old) {
        struct dump_rcu *n = kd__kmalloc(sizeof(*n), GFP_KERNEL);
        if (!n) {
            /* 兜底：当前上下文直接 fput */
            kd___fput(old);
        } else {
            INIT_LIST_HEAD(&n->list);
            n->f = old;
            kd__call_rcu(&n->rcu, dump_fput_rcu);
        }
    }
}


/* ---------- 通过 FD 写一行（优先） ---------- */
static void vm_write_line_fd_only(const char *line)
{
    struct file *filp;
    char buf[1600];
    struct timespec64 ts;
    int n;
    loff_t pos = 0;           /* 是否 O_APPEND 由用户态 open 决定 */

    if (!line || !*line) return;

    /* 写之前顺手 drain 一下挂起 fput（轻量） */
    dump_fput_drain_list();

    /* 快照当前 file*，不会临时 get_file；因为全局仍持有引用 */
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_dump_lock);
    filp = g_dump_file;
    kd___raw_spin_unlock_irqrestore(&g_dump_lock, flags);

    if (!filp) {
        // logkd("vm_write_line_fd_only:%s", "filp is empty");
        return;

    }

    kd___ktime_get_real_ts64(&ts);
    n = kd__scnprintf(buf, sizeof(buf), "[ %lld.%06ld ] %s\n",
                      (long long)ts.tv_sec, ts.tv_nsec / 1000, line);
    if (n > 0) {
        ssize_t w = kd___kernel_write(filp, buf, n, &pos);
        if (w < 0) logkd("[vm] kernel_write(fd=%p) err=%zd", filp, w);
    }
}

/* ---------- 统一写接口：优先 FD，失败再路径 ---------- */
static void vm_write_line(const char *line){
    vm_write_line_fd_only(line);
    if (g_vm_dump_dir[0]) vm_append_line_to_unified_file_path(line);
}

/* ---------- hexdump：左 HEX 右 ASCII ---------- */
static inline bool vm_is_printable(unsigned char c){ return (c >= 0x20 && c <= 0x7e); }

static void vm_hexdump_emit_line(const u8 *row, size_t rowlen){
    char line[16*3 + 16 + 2 + 16 + 2 + 8];
    size_t off = 0;

    for (size_t i = 0; i < 16; ++i) {
        if (i < rowlen) off += kd__scnprintf(line + off, sizeof(line) - off, "%02x ", row[i]);
        else            off += kd__scnprintf(line + off, sizeof(line) - off, "   ");
        if (i == 7)     off += kd__scnprintf(line + off, sizeof(line) - off, " ");
    }
    off += kd__scnprintf(line + off, sizeof(line) - off, " |");
    for (size_t i = 0; i < rowlen; ++i) line[off++] = vm_is_printable((unsigned char)row[i]) ? row[i] : '.';
    for (size_t i = rowlen; i < 16; ++i) line[off++] = ' ';
    line[off++] = '|';
    line[off]   = '\0';
    vm_write_line(line);
}

/* 把一段“内核缓冲”做 hexdump */
static void vm_hexdump_buffer_to_file(const u8 *buf, size_t len, const char *title){
    if (!buf || !len) return;
    if (title && *title) vm_write_line(title);
    for (size_t off = 0; off < len; off += 16) {
        size_t row = (len - off) < 16 ? (len - off) : 16;
        vm_hexdump_emit_line(buf + off, row);
    }
}

/* 从 __user 指针分块拷 + hexdump */
static void vm_dump_user_hexdump_to_file(const void __user *uaddr, size_t len, const char *title){
    if (!uaddr || !len) return;
    // logkd("vm_dump_user_hexdump_to_file %d %s", len, title);
    u8 *chunk = kd__kmalloc(VM_HEX_READ_CHUNK, GFP_KERNEL);
    if (!chunk){ logkd("[vm] hexdump kmalloc fail"); return; }

    if (title && *title) vm_write_line(title);

    u8 linebuf[16]; size_t linefill = 0;
    size_t done = 0;
    while (done < len) {
        size_t want = len - done; if (want > VM_HEX_READ_CHUNK) want = VM_HEX_READ_CHUNK;
        int n = kd__access_process_vm(current, (unsigned long)uaddr + done, chunk, want, 0);
        if (n <= 0){ logkd("[vm] hexdump copy fail"); break; }
        size_t got = (size_t)n;

        size_t pos = 0;
        while (pos < got) {
            size_t can  = 16 - linefill;
            size_t take = (got - pos < can) ? (got - pos) : can;
            memcpy(linebuf + linefill, chunk + pos, take);
            linefill += take; pos += take;
            if (linefill == 16) { vm_hexdump_emit_line(linebuf, 16); linefill = 0; }
        }
        done += got;
    }
    kd__kfree(chunk);
}

/* ---------- 其余原有代码（repl/range/addr 解析等） ---------- */
struct vm_so_range{
    char* name; u64 start; u64 end;
    struct list_head list; struct rcu_head rcu;
};
struct vm_repl_rule{
    char* path; u64 file_off; u8 *data; size_t data_len;
    struct list_head list; struct rcu_head rcu;
};

static void vm_repl_free_rcu(struct rcu_head *rcu){
    struct vm_repl_rule *r = container_of(rcu, struct vm_repl_rule, rcu);
    if (!r) return; if (r->path) kd__kfree(r->path); if (r->data) kd__kfree(r->data); kd__kfree(r);
}
static const struct vm_repl_rule* vm_repl_find(const char *path, u64 file_off){
    const struct vm_repl_rule *hit = NULL; struct vm_repl_rule *cur;
    kd_rcu_read_lock();
    list_for_each_entry_rcu(cur, &g_vm_repl_rules, list) {
        if (cur->file_off == file_off && cur->path && path && !strcmp(cur->path, path)) { hit = cur; break; }
    }
    kd_rcu_read_unlock(); return hit;
}
static int vm_repl_add_or_update(const char *path, u64 file_off, const u8 *data, size_t data_len){
    if (!path || !*path || !data || data_len == 0) return -EINVAL;
    struct vm_repl_rule *nr = kd__kmalloc(sizeof(*nr), GFP_KERNEL); if (!nr) return -ENOMEM;
    kd___memset(nr, 0, sizeof(*nr));
    nr->path = kd__kstrdup(path, GFP_KERNEL); if (!nr->path){ kd__kfree(nr); return -ENOMEM; }
    nr->data = kd__kmalloc(data_len, GFP_KERNEL); if (!nr->data){ kd__kfree(nr->path); kd__kfree(nr); return -ENOMEM; }
    memcpy(nr->data, data, data_len); nr->data_len = data_len; nr->file_off = file_off;

    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_repl_lock);
    struct vm_repl_rule *cur;
    list_for_each_entry(cur, &g_vm_repl_rules, list) {
        if (cur->file_off == file_off && cur->path && !strcmp(cur->path, path)) {
            nr->list = cur->list; list_replace_rcu(&cur->list, &nr->list);
            kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
            kd__call_rcu(&cur->rcu, vm_repl_free_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list); list_add_rcu(&nr->list, &g_vm_repl_rules);
    kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
    return 0;
}
static int vm_repl_del(const char *path, u64 file_off){
    if (!path || !*path) return -EINVAL;
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_repl_lock);
    struct vm_repl_rule *cur;
    list_for_each_entry(cur, &g_vm_repl_rules, list) {
        if (cur->file_off == file_off && cur->path && !strcmp(cur->path, path)) {
            list_del_rcu(&cur->list);
            kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
            kd__call_rcu(&cur->rcu, vm_repl_free_rcu);
            return 0;
        }
    }
    kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
    return -ENOENT;
}
static void vm_repl_clear(void){
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_repl_lock);
    while (!list_empty(&g_vm_repl_rules)) {
        struct vm_repl_rule *cur = list_first_entry(&g_vm_repl_rules, struct vm_repl_rule, list);
        list_del_rcu(&cur->list);
        kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
        kd__call_rcu(&cur->rcu, vm_repl_free_rcu);
        flags = kd___raw_spin_lock_irqsave(&g_vm_repl_lock);
    }
    kd___raw_spin_unlock_irqrestore(&g_vm_repl_lock, flags);
}

static void free_vm_range_rcu(struct rcu_head *rcu){
    struct vm_so_range *r = container_of(rcu, struct vm_so_range, rcu);
    if (r) { if (r->name) kd__kfree(r->name); kd__kfree(r); }
}
static int vm_range_add_or_update(const char *name, u64 start, u64 end){
    if (!name || !*name) return -EINVAL; if (start && end && start > end) return -EINVAL;
    struct vm_so_range *nr = kd__kmalloc(sizeof(*nr), GFP_KERNEL); if (!nr) return -ENOMEM;
    kd___memset(nr, 0, sizeof(*nr)); nr->name = kd__kstrdup(name, GFP_KERNEL); if (!nr->name){ kd__kfree(nr); return -ENOMEM; }
    nr->start = start; nr->end = end;

    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_ranges_lock);
    struct vm_so_range *cur;
    list_for_each_entry(cur, &g_vm_ranges, list) {
        if (!strcmp(cur->name, name)) {
            nr->list = cur->list; list_replace_rcu(&cur->list, &nr->list);
            kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
            kd__call_rcu(&cur->rcu, free_vm_range_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list); list_add_rcu(&nr->list, &g_vm_ranges);
    kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
    return 0;
}
static int vm_range_del(const char *name){
    if (!name || !*name) return -EINVAL;
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_ranges_lock);
    struct vm_so_range *cur;
    list_for_each_entry(cur, &g_vm_ranges, list) {
        if (!strcmp(cur->name, name)) {
            list_del_rcu(&cur->list);
            kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
            kd__call_rcu(&cur->rcu, free_vm_range_rcu);
            return 0;
        }
    }
    kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
    return -ENOENT;
}
static void vm_range_clear(void){
    unsigned long flags = kd___raw_spin_lock_irqsave(&g_vm_ranges_lock);
    while (!list_empty(&g_vm_ranges)) {
        struct vm_so_range *cur = list_first_entry(&g_vm_ranges, struct vm_so_range, list);
        list_del_rcu(&cur->list);
        kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
        kd__call_rcu(&cur->rcu, free_vm_range_rcu);
        flags = kd___raw_spin_lock_irqsave(&g_vm_ranges_lock);
    }
    kd___raw_spin_unlock_irqrestore(&g_vm_ranges_lock, flags);
}
static const struct vm_so_range* vm_range_find_by_pc(u64 pc){
    const struct vm_so_range *hit = NULL; struct vm_so_range *r;
    kd_rcu_read_lock();
    list_for_each_entry_rcu(r, &g_vm_ranges, list) {
        if ((!r->start && !r->end) || (r->start <= pc && pc <= r->end)) { hit = r; break; }
    }
    kd_rcu_read_unlock(); return hit;
}

size_t lib_strlcpy(char *dst, const char *src, size_t size){
    size_t bytes = 0; char *q = dst; const char *p = src; char ch;
    while ((ch = *p++)) { if (bytes + 1 < size) *q++ = ch; bytes++; }
    if (size) *q = '\0'; return bytes;
}

static inline void sanitize_cstr(char *s){ if (!s) return; for (; *s; ++s) { unsigned char c = (unsigned char)*s; if (c < 0x20 || c == 0x7f) *s = '?'; } }

static int copy_remote_cstring(struct task_struct *tsk, unsigned long uaddr, char *out, size_t cap){
    if (!out || cap < 2 || !uaddr) return -EINVAL;
    size_t done = 0; int ret = 0; char tmp[64];
    while (done < cap - 1) {
        size_t want = sizeof(tmp); if (sizeof(tmp) > (cap - 1 - done)) want = cap - 1 - done;
        int n = kd__access_process_vm(tsk, uaddr + done, tmp, want, 0);
        if (n <= 0) { logkd("[vm] anon_name read fail: n=%d uaddr=0x%lx done=%zu", n, uaddr, done); ret = n ? n : -EFAULT; break; }
        for (int i = 0; i < n && done < cap - 1; i++) { out[done++] = tmp[i]; if (tmp[i] == '\0') { out[done] = '\0'; return 0; } }
    }
    out[cap - 1] = '\0'; return ret;
}

static int vm_resolve_remote_addr(pid_t pid, unsigned long long addr,
                                  char *out_path, size_t path_cap,
                                  unsigned long long *out_vstart,
                                  unsigned long long *out_vend,
                                  unsigned long long *out_file_off,
                                  unsigned long *out_flags)
{
    int ret = -ENOENT;
    struct task_struct *tsk; struct mm_struct *mm = NULL;

    kd_rcu_read_lock();
    tsk = kd__find_task_by_vpid(pid);
    if (tsk) mm = kd__get_task_mm(tsk);
    kd_rcu_read_unlock();

    if (!mm) { lib_strlcpy(out_path, "[no-mm]", path_cap); if (out_flags) *out_flags = 0; return -EINVAL; }

    struct rw_semaphore *sem = mm_mmap_sem_ptr(mm);
    struct vm_area_struct *vma = NULL;
    unsigned long vm_start = 0, vm_end = 0;
    unsigned long vm_pgoff = 0; unsigned long vm_flags = 0;
    struct file *vm_file = NULL;
    unsigned long anon_name_uaddr = 0;
    const char *archname = NULL;

    if (sem && kd__down_read_trylock(sem)) {
        vma = kd_find_vma(mm, (unsigned long)addr);
        if (vma && addr >= READ_ONCE(*(unsigned long *)((char*)vma + 0x0))) {
            vm_start = vma_start_val(vma);
            vm_end   = vma_end_val(vma);
            if (!(addr >= vm_start && addr < vm_end)) {
                kd__up_read(sem); kd__mmput(mm);
                lib_strlcpy(out_path, "[no-vma]", path_cap); if (out_flags) *out_flags = 0;
                return -ENOENT;
            }
            vm_pgoff = vma_pgoff_val(vma);
            vm_file  = vma_file_ptr(vma);
            archname = kd__arch_vma_name ? kd__arch_vma_name(vma) : NULL;
            anon_name_uaddr = (unsigned long)(uintptr_t)vma_anon_name_ptr(vma);
            vm_flags = vma_flags_val(vma);
            ret = 0;
        }
        kd__up_read(sem);
    }

    if (ret) { kd__mmput(mm); lib_strlcpy(out_path, "[no-vma]", path_cap); if (out_flags) *out_flags = 0; return ret; }

    *out_vstart   = vm_start;
    *out_vend     = vm_end;
    *out_file_off = ((unsigned long long)vm_pgoff << PAGE_SHIFT)
                    + ((unsigned long long)addr - vm_start);

    if (vm_file) {
        char *tmp = kd__kmalloc(VM_PATH_BUF, GFP_KERNEL);
        if (!tmp) { kd__mmput(mm); if (out_flags) *out_flags = 0; return -ENOMEM; }
        char *p = kd__d_path(&vm_file->f_path, tmp, VM_PATH_BUF);
        if (IS_ERR(p)) lib_strlcpy(out_path, "[path-error]", path_cap);
        else           lib_strlcpy(out_path, p, path_cap);
        kd__kfree(tmp); kd__mmput(mm);
        if (out_flags){*out_flags = vm_flags;}
        return 0;
    }

    if (archname && *archname) {
        int n = kd__scnprintf(out_path, path_cap, "[%s]", archname);
        if (n <= 0) lib_strlcpy(out_path, "[anon]", path_cap);
        kd__mmput(mm); if (out_flags){*out_flags = vm_flags;} return 1;
    }

    if (anon_name_uaddr) {
        char namebuf[128];
        int cr = copy_remote_cstring(tsk, anon_name_uaddr, namebuf, sizeof(namebuf));
        if (cr == 0 && namebuf[0]) {
            kd__scnprintf(out_path, path_cap, "[anon:%s]", namebuf);
            kd__mmput(mm); if (out_flags){*out_flags = vm_flags;} return 1;
        }
    }

    if (out_flags){*out_flags = vm_flags;}
    lib_strlcpy(out_path, "[anon]", path_cap); kd__mmput(mm); return 1;
}

static void vm_dump_user_hex(const void __user *uaddr, size_t len, size_t *dumped_total){
    if (!len || *dumped_total >= VM_MAX_DUMP_TOTAL) return;
    size_t want = len; if (want > VM_MAX_DUMP_PER_IOV) want = VM_MAX_DUMP_PER_IOV;
    if (want + *dumped_total > VM_MAX_DUMP_TOTAL) want = VM_MAX_DUMP_TOTAL - *dumped_total;
    if (!want) return;

    u8* tmp = kd__memdup_user(uaddr, want);
    if (IS_ERR(tmp)){ long err = PTR_ERR(tmp); logkd("[vm] memdup_user failed: %ld", err); return; }

    char line[VM_MAX_DUMP_PER_IOV * 2 + 32];
    size_t off = 0;
    off += kd__scnprintf(line+off, sizeof(line)-off, "line=%zu data=", len);
    for (size_t i = 0; i < want && off + 2 < sizeof(line); i++) off += kd__scnprintf(line + off, sizeof(line) - off, "%02x", tmp[i]);
    if (want < len) off += kd__scnprintf(line + off, sizeof(line) - off, "...(+%zu)", len - want);
    logkd("[vm] %s", line);

    *dumped_total += want; kd__kfree(tmp);
}

static int vm_copy_iovecs_from_user(const struct iovec __user *uiov, unsigned long cnt, struct iovec **out_k, gfp_t gfp){
    size_t sz; struct iovec *k; if (!out_k) return -EINVAL; *out_k = NULL;
    if (!cnt) return 0; if (!uiov) return -EINVAL;
    if (cnt > (~0UL / sizeof(*k))) return -E2BIG;
    sz = cnt * sizeof(*k);
    k = kd__memdup_user(uiov, sz); if (IS_ERR(k)) return PTR_ERR(k);
    *out_k = k; return 0;
}

struct rmeta {
    char path[VM_PATH_BUF];
    u64  off_base;
    size_t len;
    bool has_file;
    unsigned long flags;
    char perms[5];
};

static __always_inline unsigned long untagged_addr(unsigned long addr)
{
    /* 顶字节掩码：0xFF << 56 */
    const unsigned long TOP_BYTE_MASK = (~0UL) << 56;   // = 0xFF00000000000000UL
    return addr & ~TOP_BYTE_MASK;
}

static u64 vm_caller_pc(struct pt_regs *regs, u64 start){
    unsigned long elr = regs->user_regs.pc;
    unsigned long svcpc = elr - 4;
    unsigned long lr = regs->user_regs.regs[30];
    unsigned long callsite_doSyscall = lr - 4;
    unsigned long fp = regs->user_regs.regs[29];
    fp = untagged_addr(fp);
    unsigned long caller_lr = 0;
    const void __user *uaddr = (const void __user*)(fp+8);
    u64 *tmp = (u64 *)kd__memdup_user(uaddr,sizeof(u64));
    if (!IS_ERR(tmp)){
        caller_lr = (unsigned long)(*tmp);
        kd__kfree(tmp);
    }else{
        long err = PTR_ERR(tmp);
        // logkd("[vm] caller_pc: memdup_user([fp+8]) failed: %ld (fp=0x%lx)\n", err, fp);
    }
    unsigned long callsite_vm_readv = caller_lr ? (caller_lr - start - 4) : 0; // 期望 0xA1114
    // logkd("[vm] ELR=0x%lx SVC@0x%lx LR=0x%lx doSysBL@0x%lx prevLR=0x%lx prevBL@0x%lx\n",
    //          elr, svcpc, lr, callsite_doSyscall, caller_lr, callsite_vm_readv);
    return callsite_vm_readv;
}

static ssize_t replace_process_vm_rw(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt,
                    const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags, int vm_write)
{
    if (!is_vm_uid()) return backup_process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write);

    struct task_struct *task = current;
    struct pt_regs *regs = _task_pt_reg(task);
    if (!regs) return backup_process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write);

    u64 pc = regs->user_regs.regs[30];
    const struct vm_so_range *hit = vm_range_find_by_pc(pc);
    if (!hit) return backup_process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write);
    
    const char *so_name = hit ? hit->name : "unknown";
    u64 offset = hit ? (pc - hit->start) : pc;

    u64 caller_offset = vm_caller_pc(regs, hit->start);

    struct rmeta *rm = NULL;
    if (riovcnt) { rm = kd__kmalloc(sizeof(*rm) * riovcnt, GFP_KERNEL); if (rm) kd___memset(rm, 0, sizeof(*rm) * riovcnt); }
    struct iovec *lk = NULL, *rk = NULL;
    int errl = vm_copy_iovecs_from_user(lvec, liovcnt, &lk, GFP_KERNEL);
    int errr = vm_copy_iovecs_from_user(rvec, riovcnt, &rk, GFP_KERNEL);
    if (errl || errr){ if (lk)kd__kfree(lk); if (rk)kd__kfree(rk); return backup_process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write); }

        if (!vm_write) {
        bool trigger = false;
        /* 我们还没拿到 file* 时才去看是否触发 */
        unsigned long flg = kd___raw_spin_lock_irqsave(&g_dump_lock);
        bool need_resolve = (g_dump_file == NULL && g_dump_fdno >= 0);
        kd___raw_spin_unlock_irqrestore(&g_dump_lock, flg);

        if (need_resolve) {
            /* 粗判是否出现大块 */
            for (unsigned long i = 0; i < liovcnt; i++) {
                if (lk && lk[i].iov_len >= 4096) { trigger = true; break; }
            }
            if (trigger) vm_maybe_resolve_dump_file();
        }
    }

    size_t dumped_total = 0;
    if (vm_write){
        for(unsigned long i=0; i < liovcnt && dumped_total < VM_MAX_DUMP_TOTAL; i++){
            if (!lk[i].iov_len || !lk[i].iov_base) continue;
            logkd("[vm] pc=0x%llx so=%s off=0x%llx offup=0x%llx WRITE local[%lu] ptr=%p len=%zu", pc,so_name,offset,caller_offset,i, lk[i].iov_base, lk[i].iov_len);
            vm_dump_user_hex(lk[i].iov_base, lk[i].iov_len, &dumped_total);
        }
    }

    ssize_t ret = backup_process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, vm_write);

    for(unsigned long i = 0;i < riovcnt; i++){
        if (!rk[i].iov_len) { if (rm) rm[i].len = 0; continue; }
        unsigned long long raddr = (unsigned long long)(uintptr_t)rk[i].iov_base;
        unsigned long vstart = 0, vend = 0, pgoff = 0;
        char* pathbuf = kd__kmalloc(VM_PATH_BUF, GFP_KERNEL);
        if (!pathbuf){ if (rm) rm[i].len = 0; continue; }
        int r = 0; unsigned long vflags = 0;
        r = vm_resolve_remote_addr(pid, raddr, pathbuf, VM_PATH_BUF, &vstart,&vend,&pgoff, &vflags);
        char perms[5]; vm_flags_to_perm(vflags, perms);
        if (r == 1) {
            logkd("[vm] pc=0x%llx so=%s off=0x%llx offup=0x%llx REMOTE[%lu] addr=0x%llx len=%zu -> %s [0x%llx-0x%llx] perms=%s",
                    pc, so_name, offset, caller_offset, i, raddr, rk[i].iov_len, pathbuf, vstart, vend, perms);
            if (rm) { kd____strlcpy(rm[i].path, pathbuf, sizeof(rm[i].path)); rm[i].len = rk[i].iov_len; rm[i].off_base = 0; rm[i].has_file = false; rm[i].flags = vflags; vm_flags_to_perm(vflags, rm[i].perms); }
        }else if (r == 0){
            logkd("[vm] pc=0x%llx so=%s off=0x%llx offup=0x%llx REMOTE[%lu] addr=0x%llx len=%zu -> %s [0x%llx-0x%llx] file_off=0x%llx perms=%s",
                    pc, so_name, offset, caller_offset, i, raddr, rk[i].iov_len, pathbuf, vstart, vend, pgoff, perms);
            if (rm) { kd____strlcpy(rm[i].path, pathbuf, sizeof(rm[i].path)); rm[i].len = rk[i].iov_len; rm[i].off_base = pgoff; rm[i].has_file = true; rm[i].flags = vflags; vm_flags_to_perm(vflags, rm[i].perms); }
        } else {
            logkd("[vm] pc=0x%llx so=%s off=0x%llx offup=0x%llx REMOTE[%lu] addr=0x%llx len=%zu -> [no vma]", 
                pc, so_name, offset, caller_offset, i, raddr, rk[i].iov_len);
            if (rm) { rm[i].path[0] = 0; rm[i].len = rk[i].iov_len; rm[i].off_base = 0; rm[i].has_file = false; rm[i].flags = vflags; vm_flags_to_perm(vflags, rm[i].perms); }
        }
        kd__kfree(pathbuf);
    }

    /* 替换逻辑 */
    if (!vm_write && ret > 0 && lk && rk && rm) {
        unsigned long li = 0, ri = 0; size_t loff = 0, roff = 0;
        while (li < liovcnt && ri < riovcnt) {
            while (li < liovcnt && (lk[li].iov_len == 0 || lk[li].iov_base == NULL)) li++;
            while (ri < riovcnt && (rk[ri].iov_len == 0)) ri++;
            if (li >= liovcnt || ri >= riovcnt) break;

            size_t lrem = lk[li].iov_len - loff;
            size_t rrem = rk[ri].iov_len - roff;
            size_t chunk = (lrem < rrem) ? lrem : rrem;
            if (chunk == 0) { if (lrem == 0) { li++; loff = 0; } if (rrem == 0) { ri++; roff = 0; } continue; }

            if (rm[ri].has_file && rm[ri].path[0]) {
                u64 cur_file_off = rm[ri].off_base + roff;
                const struct vm_repl_rule *rule = vm_repl_find(rm[ri].path, cur_file_off);
                if (rule && rule->data && rule->data_len > 0) {
                    size_t n = chunk; if (n > rule->data_len) n = rule->data_len;
                    if (n) {
                        void __user *dst = (void __user *)((unsigned long)lk[li].iov_base + loff);
                        size_t copied = 0;
                        while (copied < n) {
                            size_t frag = n - copied; if (frag > 0x1000) frag = 0x1000;
                            if (compat_copy_to_user((u8 __user *)dst + copied, rule->data + copied, frag) <= 0) {
                                logkd("[vm] replace copy_to_user failed at li=%lu off=%zu size=%zu", li, loff+copied, frag);
                                break;
                            }
                            copied += frag;
                        }
                        if (copied > 0) logkd("[vm] REPLACED path=%s file_off=0x%llx bytes=%zu", rule->path, cur_file_off, copied);
                    }
                }
            }
            loff += chunk; roff += chunk;
            if (loff >= lk[li].iov_len) { li++; loff = 0; }
            if (roff >= rk[ri].iov_len) { ri++; roff = 0; }
        }
    }

    /* READ 后落盘（筛选固定长度） */
    if (!vm_write && ret > 0){
        dumped_total = 0;
        for (unsigned long i=0;i<liovcnt && dumped_total < VM_MAX_DUMP_TOTAL;i++){
            if (!lk[i].iov_len || !lk[i].iov_base) continue;

            // size_t want = (lk[i].iov_len == 4) ? 32 : lk[i].iov_len;
            // if (want > VM_MAX_DUMP_PER_IOV) want = VM_MAX_DUMP_PER_IOV;
            // if (dumped_total + want > VM_MAX_DUMP_TOTAL) want = VM_MAX_DUMP_TOTAL - dumped_total;
            // if (want == 0) break;

            // // logkd("[vm] pc=0x%llx so=%s off=0x%llx offup=0x%llx READ local[%lu] ptr=%p len=%zu", 
            // //     pc,so_name,offset, caller_offset, i, lk[i].iov_base, lk[i].iov_len);
            // /* 从远端地址读（而不是从本地 lk[i].iov_base 超界打印） */
            // if (i < riovcnt && rk && rk[i].iov_base && rk[i].iov_len) {
            //     u8 *tmp = kd__kmalloc(want, GFP_KERNEL);
            //     if (!tmp) break;
            //     int n = kd__access_process_vm(current, (unsigned long)rk[i].iov_base, tmp, want, 0);
            //     if (n > 0) {
            //         char line[32 * 2 + 32];
            //         size_t off = 0;
            //         off += kd__scnprintf(line + off, sizeof(line) - off, "line=%d data=", 32);
            //         for (int i = 0; i < n && off + 2 < sizeof(line); ++i) {
            //             off += kd__scnprintf(line + off, sizeof(line) - off, "%02x", tmp[i]);
            //         }
            //         if (n < 32) {
            //             off += kd__scnprintf(line + off, sizeof(line) - off, "...(+%d)", 32 - n);
            //         }
            //         logkd("[vm] %s", line);
            //         dumped_total += n; // 
            //     } else {
            //         logkd("[vm] peek remote fail: i=%lu addr=0x%llx want=%zu n=%d",
            //             i,
            //             (unsigned long long)(uintptr_t)rk[i].iov_base,
            //             want, n);
            //     }
            //     kd__kfree(tmp);
            // }else{
            //     vm_dump_user_hex(lk[i].iov_base, lk[i].iov_len, &dumped_total);
            // }

            vm_dump_user_hex(lk[i].iov_base, lk[i].iov_len, &dumped_total);

            size_t L = lk[i].iov_len;
            if (L == 216 || L == 4096 || L == 8192 || L == 16384) {
                char title[256];
                // kd__scnprintf(title, sizeof(title), "[vm] hexdump pc=0x%llx so=%s READ local[%lu] len=%zu", pc, so_name, i, L);
                vm_dump_user_hexdump_to_file(lk[i].iov_base, L, title);
            }
        }
    }

    if (lk) kd__kfree(lk); if (rk) kd__kfree(rk); if (rm) kd__kfree(rm);
    return ret;
}

static inline bool hook_process_vm_rw(){
    if (origin_process_vm_rw){
        hook_err_t hook_err = hook((void *)origin_process_vm_rw, (void *)replace_process_vm_rw, (void **)&backup_process_vm_rw);
        if (hook_err != HOOK_NO_ERR){ vm_hooked = false; logkd("vm hook process_vm_rw, %llx, error: %d", origin_process_vm_rw, hook_err); }
        else { vm_hooked = true; return true; }
    }else{
        vm_hooked = false; logkd("%s","vm no symbol: process_vm_rw");
    }
    return false;
}

static inline bool install_hook(){
    if (!vm_hooked) { if (hook_process_vm_rw()){ logkd("%s","vm hook installed..."); return true; } else { logkd("%s","vm installation failed..."); } }
    return false;
}

static inline void uninstall_hook(){
    if (vm_hooked && origin_process_vm_rw){ unhook((void *)origin_process_vm_rw); vm_hooked = false; logkd("%s","hook uninstalled..."); }
}

/* ===== 初始化/反初始化 ===== */
int evm_init(){
    spin_lock_init(&g_dump_lock);
    spin_lock_init(&g_pending_fput_lock);
    INIT_LIST_HEAD(&g_pending_fput);
    spin_lock_init(&g_vm_ranges_lock);
    spin_lock_init(&g_vm_repl_lock);
    g_dump_fdno = -1;
    g_dump_file = NULL;

    kd_rcu_read_lock = (void *)kallsyms_lookup_name("__rcu_read_lock");
    kd_rcu_read_unlock = (void *)kallsyms_lookup_name("__rcu_read_unlock");
    kd__call_rcu = (void *)kallsyms_lookup_name("call_rcu");
    kd__kmalloc = (void *)kallsyms_lookup_name("__kmalloc");
    kd__kfree = (void*)kallsyms_lookup_name("kfree");
    kd___memset = (void*)kallsyms_lookup_name("memset");
    kd__kstrdup = (void*)kallsyms_lookup_name("kstrdup");
    kd_kstrtoint = (void*)kallsyms_lookup_name("kstrtoint");
    kd__kstrtoull = (void*)kallsyms_lookup_name("kstrtoull");
    kd__scnprintf = (void*)kallsyms_lookup_name("scnprintf");
    kd__down_read = (void*)kallsyms_lookup_name("down_read");
    kd__up_read = (void*)kallsyms_lookup_name("up_read");
    kd__find_vpid = (void*)kallsyms_lookup_name("find_vpid");
    kd__pid_task = (void*)kallsyms_lookup_name("pid_task");
    kd__get_task_mm = (void*)kallsyms_lookup_name("get_task_mm");
    kd____put_task_struct = (void*)kallsyms_lookup_name("__put_task_struct");
    kd_find_vma = (void*)kallsyms_lookup_name("find_vma");
    kd__mmput = (void*)kallsyms_lookup_name("mmput");
    kd____strlcpy = (void*)kallsyms_lookup_name("strlcpy");
    kd__kern_path = (void*)kallsyms_lookup_name("kern_path");
    kd__d_path = (void*)kallsyms_lookup_name("d_path");
    kd__path_put = (void*)kallsyms_lookup_name("path_put");
    kd__memdup_user = (void*)kallsyms_lookup_name("memdup_user");
    kd__find_task_by_vpid = (void*)kallsyms_lookup_name("find_task_by_vpid");
    kd__down_read_trylock = (void*)kallsyms_lookup_name("down_read_trylock");
    kd__arch_vma_name = (void*)kallsyms_lookup_name("arch_vma_name");
    kd__access_process_vm = (void*)kallsyms_lookup_name("access_process_vm");
    kd__sscanf = (void*)kallsyms_lookup_name("sscanf");
    kd___ktime_get_real_ts64 = (void*)kallsyms_lookup_name("ktime_get_real_ts64");
    kd___filp_close = (void*)kallsyms_lookup_name("filp_close");
    kd___filp_open = (void*)kallsyms_lookup_name("filp_open");
    kd___kernel_write = (void*)kallsyms_lookup_name("kernel_write");
    kd___fget = (void*)kallsyms_lookup_name("fget");
    kd___fput = (void*)kallsyms_lookup_name("fput");
    kd___raw_spin_lock_irqsave = (void*)kallsyms_lookup_name("_raw_spin_lock_irqsave");
    kd___raw_spin_unlock_irqrestore = (void*)kallsyms_lookup_name("_raw_spin_unlock_irqrestore");

    origin_process_vm_rw = (process_vm_rw_func_t)kallsyms_lookup_name("process_vm_rw");

    logkd("rcu_read_lock:%p", kd_rcu_read_lock);
    logkd("rcu_read_unlock:%p", kd_rcu_read_unlock);
    logkd("call_rcu:%p", kd__call_rcu);
    logkd("__kmalloc:%p", kd__kmalloc);
    logkd("kfree:%p", kd__kfree);
    logkd("memset:%p", kd___memset);
    logkd("kstrdup:%p", kd__kstrdup);
    logkd("kstrtoint:%p", kd_kstrtoint);
    logkd("kstrtoull:%p", kd__kstrtoull);
    logkd("scnprintf:%p", kd__scnprintf);
    logkd("down_read:%p", kd__down_read);
    logkd("up_read:%p", kd__up_read);
    logkd("find_vpid:%p", kd__find_vpid);
    logkd("pid_task:%p", kd__pid_task);
    logkd("get_task_mm:%p", kd__get_task_mm);
    logkd("find_vma:%p", kd_find_vma);
    logkd("mmput:%p", kd__mmput);
    logkd("d_path:%p", kd__d_path);
    logkd("memdup_user:%p", kd__memdup_user);
    logkd("down_read_trylock:%p", kd__down_read_trylock);
    logkd("access_process_vm:%p", kd__access_process_vm);
    logkd("arch_vma_name:%p", kd__arch_vma_name);
    logkd("ktime_get_real_ts64:%p", kd___ktime_get_real_ts64);
    logkd("filp_open:%p", kd___filp_open);
    logkd("filp_close:%p", kd___filp_close);
    logkd("kernel_write:%p", kd___kernel_write);
    logkd("fget:%p", kd___fget);
    logkd("fput:%p", kd___fput);
    logkd("_raw_spin_lock_irqsave:%p", kd___raw_spin_lock_irqsave);
    logkd("_raw_spin_unlock_irqrestore:%p", kd___raw_spin_unlock_irqrestore);
    logkd("process_vm_rw:%llx", origin_process_vm_rw);
    return 0;
}

static int parse_hex_bytes(const char *s, u8 **out, size_t *out_len){
    if (!s || !out || !out_len) return -EINVAL;
    size_t L = strlen(s); char *buf = kd__kmalloc(L + 1, GFP_KERNEL); if (!buf) return -ENOMEM;
    size_t w = 0; for (size_t i = 0; i < L; i++) { char c = s[i]; if (c == ' ' || c == '\t' || c == '\n') continue; buf[w++] = c; }
    buf[w] = 0; if (w == 0 || (w & 1)) { kd__kfree(buf); return -EINVAL; }

    size_t n = w / 2; u8 *outbuf = kd__kmalloc(n, GFP_KERNEL); if (!outbuf) { kd__kfree(buf); return -ENOMEM; }
    for (size_t i = 0; i < n; i++) { char hh[3] = { buf[i*2], buf[i*2+1], 0 }; unsigned int byte = 0;
        if (kd__sscanf(hh, "%02x", &byte) != 1) { kd__kfree(outbuf); kd__kfree(buf); return -EINVAL; }
        outbuf[i] = (u8)byte;
    }
    kd__kfree(buf); *out = outbuf; *out_len = n; return 0;
}

/* ===== 命令入口 ===== */
int evm_main(struct opts *opts){
    int err = 0; if (opts->size < 3) return -EINVAL;

    err = kd_kstrtoint(opts->args[1], 10, &r_vm_target_uid);
    if (err) r_vm_target_uid = -1;

    /* dump 子命令 */
    if (!strcmp(opts->args[2], "dump") && opts->size >= 4) {
        const char *sub = opts->args[3];

        /* dump fd <number> */
        if (!strcmp(sub, "fd") && opts->size >= 5) {
            int fdnum = -1; kd_kstrtoint(opts->args[4], 10, &fdnum);
            int rc = vm_set_dump_fd(fdnum);
            logkd("[vm] dump fd rc=%d", rc);
            return rc;
        }
        /* dump fdclose */
        if (!strcmp(sub, "fdclose")) {
            vm_clear_dump_fd();
            return 0;
        }
        /* dump dir <path> 及 clear（保留作为备选） */
        if (!strcmp(sub, "dir") && opts->size >= 5) {
            kd____strlcpy(g_vm_dump_dir, opts->args[4], sizeof(g_vm_dump_dir));
            logkd("[vm] dump dir set to: %s", g_vm_dump_dir);
            vm_write_line("[vm] dump dir set");
            return 0;
        }
        if (!strcmp(sub, "clear")) {
            int rc = vm_clear_unified_file();
            logkd("[vm] dump clear rc=%d", rc);
            return 0;
        }
        return -EINVAL;
    }

    if (!strcmp(opts->args[2], "print") && opts->size >= 4){
        g_vm_print_only = !strcmp(opts->args[3], "on");
        return 0;
    }

    if (!strcmp(opts->args[2], "hook")) { uninstall_hook(); return install_hook() ? 0 : -EINVAL; }
    if (!strcmp(opts->args[2], "unhook")) { uninstall_hook(); return 0; }

    if (!strcmp(opts->args[2],"range") && opts->size >= 4){
        const char *sub = opts->args[3];
        if (!strcmp(sub, "add") && opts->size >= 7){
            const char *name = opts->args[4]; u64 beg = 0, end = 0;
            kd__kstrtoull(opts->args[5], 10, &beg); kd__kstrtoull(opts->args[6], 10, &end);
            return vm_range_add_or_update(name, beg, end);
        }
        if (!strcmp(sub, "del") && opts->size >= 5) return vm_range_del(opts->args[4]);
        if (!strcmp(sub, "clear")) { vm_range_clear(); return 0; }
        if (!strcmp(sub, "list")){
            int i =0; kd_rcu_read_lock();
            struct vm_so_range *r; list_for_each_entry_rcu(r, &g_vm_ranges, list){
                logkd("[vm] range#%d name=%s [0x%llx - 0x%llx]", i++, r->name, r->start, r->end);
            }
            kd_rcu_read_unlock(); if (!i) logkd("[vm] no ranges"); return 0;
        }
    }

    if (!strcmp(opts->args[2], "repl") && opts->size >= 4) {
        const char *sub = opts->args[3];
        if (!strcmp(sub, "add") && opts->size >= 7) {
            const char *path = opts->args[4]; unsigned long long off = 0;
            kd__kstrtoull(opts->args[5], 0, &off);
            u8 *bytes = NULL; size_t blen = 0;
            int pe = parse_hex_bytes(opts->args[6], &bytes, &blen);
            if (pe) { logkd("[vm] repl add parse hex failed: %d", pe); return -EINVAL; }
            int re = vm_repl_add_or_update(path, off, bytes, blen);
            kd__kfree(bytes);
            logkd("[vm] repl add %s off=0x%llx len=%zu rc=%d", path, off, blen, re);
            return re;
        }
        if (!strcmp(sub, "del") && opts->size >= 6) {
            const char *path = opts->args[4]; unsigned long long off = 0;
            kd__kstrtoull(opts->args[5], 0, &off);
            int re = vm_repl_del(path, off);
            logkd("[vm] repl del %s off=0x%llx rc=%d", path, off, re);
            return re;
        }
        if (!strcmp(sub, "clear")) { vm_repl_clear(); logkd("[vm] repl clear"); return 0; }
        if (!strcmp(sub, "list")) {
            int i = 0; kd_rcu_read_lock();
            struct vm_repl_rule *r; list_for_each_entry_rcu(r, &g_vm_repl_rules, list) {
                logkd("[vm] repl#%d path=%s off=0x%llx data_len=%zu", i++, r->path, r->file_off, r->data_len);
            }
            kd_rcu_read_unlock(); if (!i) logkd("[vm] no repl rules"); return 0;
        }
    }
    return -EINVAL;
}

void evm_exit(){
    logkd("%s","evm_exit");
    uninstall_hook();
    vm_range_clear();
    vm_repl_clear();
    vm_clear_dump_fd();
    dump_fput_drain_list();  /* 确保所有挂起 fput 都释放 */
    logkd("[vm] evm_exit");
}
