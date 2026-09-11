// emaps.c  — full version (with <empty> path support)

/* =====================================================================
 * emaps.c - per-uid /proc/<pid>/maps 行级隐藏 (legacy)
 * =====================================================================
 *
 * 【跟 hide-so 的区别】
 *   hide-so 在 VMA 层面操作 (proc_maps 路径里的 dentry_name), 改的是
 *   真实的 vma->vm_file, 影响所有读者; emaps 在 seq_file 渲染层过滤,
 *   只对特定 uid 看到的 maps 文本生效, 不影响真实 VMA。
 *
 * 【保留原因】
 *   - 老测试 case 的兼容性
 *   - regex 规则 (hide-so 只支持 token substring 匹配)
 *   - 多规则叠加 (一个 uid 多条 hide 规则)
 *
 * 【实现】
 *   - 规则存成链表, 每个 rule = {pattern, type: prefix|exact|regex}
 *   - getdents64 before-hook: 仅当 caller uid == rule uid 时, 给 process
 *     的 /proc/<pid>/maps 目录条目做掩码 (可选)
 *   - seq_read after-hook: 把 maps buffer 拷到内核, 按行扫描删掉
 *     命中规则的行, 再 copy_to_user 回去
 *
 * 【懒加载】
 *   mkpm_call_dys 在首次 ctl0 "emaps ..." 时调 emaps_init, 然后
 *   emaps_main 处理具体子命令。
 */

#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include "opts.h"
#include "emaps.h"

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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    //...
};

struct hook_funcs {
    void *original;
    void *replacement;
    void **backup;
};

static LIST_HEAD(rule_list);
static spinlock_t rule_lock;
/* emaps 由 ctl0 懒加载；hide-so 的 show_map 回调可能更早执行。 */
static volatile int emaps_ready;
static volatile int emaps_hooked;
static volatile int emaps_callback_seen;
static volatile int emaps_rewrite_seen;

enum maps_rule_flags {
    MAPS_ACT_DROP       = 1 << 0,
    MAPS_ACT_REPL_INO   = 1 << 1,
    MAPS_ACT_REPL_PATH  = 1 << 2,
    MAPS_KEEP_DELETED   = 1 << 3,  // 替换 path 时是否保留 " (deleted)"
    MAPS_ACT_APPEND     = 1 << 4,  // 追加若干行
    MAPS_MATCH_SUBSTR   = 1 << 5,  // 路径采用子串匹配（match 不以 '/' 开头时自动启用）
    MAPS_ACT_SET_PERMS  = 1 << 6,  // 命中后强制设置 perms（4字节）
    MAPS_ACT_SET_ADDR   = 1 << 7,  // 命中后强制设置范围 end = start + set_span
};

struct maps_rule {
    char *match;          // 匹配的 pathname（精确或子串）；特别关键字 "<empty>" 代表“无路径”
    size_t match_len;

    u64   new_ino;        // 替换用 inode（REPL_INO）
    char *new_path;       // 替换用 pathname（REPL_PATH）
    size_t new_path_len;

    u32 flags;

    // 条件与设置
    char  cond_perms[5];  // 条件：perms（如 "r-xp"），空串=不限制
    int   cond_off_mode;  // -1=忽略；0=要求 offset==0；1=要求 offset!=0
    char  set_perms[5];   // 命中后设置 perms（SET_PERMS）
    unsigned long set_span; // 命中后设置 end = start + set_span（SET_ADDR）

    // 追加
    char *append_blob;
    size_t append_len;

    struct list_head list;
    struct rcu_head rcu;
};

static inline int seq_write_safe(struct seq_file *m, const void *data, size_t len)
{
    if (len == 0) return 0;
    if (m->count + len < m->size) {
        memcpy(m->buf + m->count, data, len);
        m->count += len;
        return 0;
    }
    m->count = m->size;
    return -EOVERFLOW;
}

static void free_rule_rcu(struct rcu_head *rcu){
    struct maps_rule *r = container_of(rcu, struct maps_rule, rcu);
    if (r && r->match_len > 0 && r->match) kf__kfree(r->match);
    if (r && r->new_path_len > 0 && r->new_path) kf__kfree(r->new_path);
    if (r && r->append_len > 0 && r->append_blob) kf__kfree(r->append_blob);
    if (r) kf__kfree(r);
}

static int add_or_update_rule_ex(const char *path,
                                 u64 newino,
                                 const char *newpath,
                                 u32 flags,
                                 const char *append_blob_opt,
                                 const char *cond_perms_opt, // 4字节或NULL
                                 int cond_off_mode_opt,       // -1/0/1
                                 const char *set_perms_opt,   // 4字节或NULL
                                 unsigned long set_span_opt)  // 仅 SET_ADDR
{
    if (!path || !*path) return -EINVAL;

    struct maps_rule *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    char *m = kf__kstrdup(path, GFP_KERNEL);
    if (!nr || !m){
        if (nr) kf__kfree(nr);
        if (m)  kf__kfree(m);
        return -ENOMEM;
    }
    kf__memset(nr, 0, sizeof(*nr));
    nr->match = m;
    nr->match_len = strlen(m);
    nr->flags = flags;

    // 兼容：非绝对路径 → 子串匹配
    if (nr->match[0] != '/') nr->flags |= MAPS_MATCH_SUBSTR;

    if (flags & MAPS_ACT_REPL_INO) nr->new_ino = newino;
    if ((flags & MAPS_ACT_REPL_PATH) && newpath){
        nr->new_path = kf__kstrdup(newpath, GFP_KERNEL);
        if (!nr->new_path){
            kf__kfree(nr->match); kf__kfree(nr);
            return -ENOMEM;
        }
        nr->new_path_len = strlen(nr->new_path);
    }
    if (flags & MAPS_ACT_SET_PERMS){
        if (set_perms_opt && strlen(set_perms_opt) >= 4){
            memcpy(nr->set_perms, set_perms_opt, 4);
            nr->set_perms[4] = '\0';
        }
    }
    if (flags & MAPS_ACT_SET_ADDR){
        nr->set_span = set_span_opt;
    }
    if (flags & MAPS_ACT_APPEND){
        if (append_blob_opt){
            nr->append_blob = kf__kstrdup(append_blob_opt, GFP_KERNEL);
            if (!nr->append_blob){
                if (nr->new_path) kf__kfree(nr->new_path);
                kf__kfree(nr->match); kf__kfree(nr);
                return -ENOMEM;
            }
            nr->append_len = strlen(nr->append_blob);
            if (nr->append_len == 0 || nr->append_blob[nr->append_len-1] != '\n'){
                char *tmp = kf__kmalloc(nr->append_len+2, GFP_KERNEL);
                if (!tmp){
                    kf__kfree(nr->append_blob);
                    if (nr->new_path) kf__kfree(nr->new_path);
                    kf__kfree(nr->match); kf__kfree(nr);
                    return -ENOMEM;
                }
                memcpy(tmp, nr->append_blob, nr->append_len);
                tmp[nr->append_len++] = '\n';
                tmp[nr->append_len] = '\0';
                kf__kfree(nr->append_blob);
                nr->append_blob = tmp;
            }
        }
    }

    // 条件键
    nr->cond_off_mode = (cond_off_mode_opt >= -1 && cond_off_mode_opt <= 1) ? cond_off_mode_opt : -1;
    if (cond_perms_opt && strlen(cond_perms_opt) >= 4){
        memcpy(nr->cond_perms, cond_perms_opt, 4);
        nr->cond_perms[4] = '\0';
    }

    // 插入或“同键替换”
    kf_spin_lock(&rule_lock);
    struct maps_rule *cur;
    list_for_each_entry(cur, &rule_list, list){
        bool same_match = (cur->match_len == nr->match_len &&
                           !memcmp(cur->match, nr->match, nr->match_len));
        bool same_subst = ((cur->flags & MAPS_MATCH_SUBSTR) == (nr->flags & MAPS_MATCH_SUBSTR));
        if (!same_match || !same_subst) continue;

        bool same_cond =
            (cur->cond_off_mode == nr->cond_off_mode) &&
            (!memcmp(cur->cond_perms, nr->cond_perms, 5));
        bool same_actions =
            ((cur->flags & (MAPS_ACT_SET_ADDR|MAPS_ACT_SET_PERMS|MAPS_ACT_REPL_INO|MAPS_ACT_REPL_PATH|MAPS_KEEP_DELETED|MAPS_ACT_DROP|MAPS_ACT_APPEND))
             ==
             (nr->flags & (MAPS_ACT_SET_ADDR|MAPS_ACT_SET_PERMS|MAPS_ACT_REPL_INO|MAPS_ACT_REPL_PATH|MAPS_KEEP_DELETED|MAPS_ACT_DROP|MAPS_ACT_APPEND)))
            && (cur->set_span == nr->set_span)
            && (!memcmp(cur->set_perms, nr->set_perms, 5))
            && ((!(nr->flags & MAPS_ACT_REPL_PATH)) ||
                (cur->new_path_len == nr->new_path_len &&
                 (!nr->new_path_len || !memcmp(cur->new_path, nr->new_path, nr->new_path_len))))
            && ((!(nr->flags & MAPS_ACT_REPL_INO)) || (cur->new_ino == nr->new_ino));

        if (same_cond && same_actions){
            nr->list = cur->list;
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&rule_lock);
            kf__call_rcu(&cur->rcu, free_rule_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &rule_list);
    kf_spin_unlock(&rule_lock);
    return 0;
}

static int add_or_update_rule(const char *path, u64 newino, const char *newpath, u32 flags, const char *append_blob_opt){
    if (!path || !*path) return -EINVAL;

    struct maps_rule *nr = kf__kmalloc(sizeof(*nr), GFP_KERNEL);
    char *m = kf__kstrdup(path, GFP_KERNEL);
    if (!nr || !m){
        if (nr) kf__kfree(nr);
        if (m)  kf__kfree(m);
        return -ENOMEM;
    }
    kf__memset(nr, 0, sizeof(*nr));
    nr->match = m;
    nr->match_len = strlen(m);
    nr->flags = flags;
    nr->cond_off_mode = -1;

    if (flags & MAPS_ACT_REPL_INO){
        nr->new_ino = newino;
    }
    if ((flags & MAPS_ACT_REPL_PATH) && newpath){
        nr->new_path = kf__kstrdup(newpath, GFP_KERNEL);
        if (!nr->new_path){
            kf__kfree(nr->match);
            kf__kfree(nr);
            return -ENOMEM;
        }
        nr->new_path_len = strlen(nr->new_path);
    }
    if ((flags & MAPS_ACT_APPEND) && append_blob_opt){
        nr->append_blob = kf__kstrdup(append_blob_opt, GFP_KERNEL);
        if (!nr->append_blob) {
            if (nr->new_path) kf__kfree(nr->new_path);
            kf__kfree(nr->match);
            kf__kfree(nr);
            return -ENOMEM;
        }
        nr->append_len = strlen(nr->append_blob);
        if (nr->append_len == 0 || nr->append_blob[nr->append_len-1] != '\n'){
            char *tmp = kf__kmalloc(nr->append_len+2, GFP_KERNEL);
            if (!tmp){
                kf__kfree(nr->append_blob);
                if (nr->new_path) kf__kfree(nr->new_path);
                kf__kfree(nr->match);
                kf__kfree(nr);
                return -ENOMEM;
            }
            memcpy(tmp, nr->append_blob, nr->append_len);
            tmp[nr->append_len++] = '\n';
            tmp[nr->append_len] = '\0';
            kf__kfree(nr->append_blob);
            nr->append_blob = tmp;
        }
    }

    if ((flags & (MAPS_ACT_DROP)) && nr->match && nr->match[0] != '/'){
        nr->flags |= MAPS_MATCH_SUBSTR;
    }
    if (nr->match && nr->match[0] != '/') {
        nr->flags |= MAPS_MATCH_SUBSTR;
    }

    kf_spin_lock(&rule_lock);
    struct maps_rule *cur;
    list_for_each_entry(cur, &rule_list, list){
        if (cur->match_len == nr->match_len &&
            !memcmp(cur->match, nr->match, nr->match_len) &&
            ((cur->flags & MAPS_MATCH_SUBSTR) == (nr->flags & MAPS_MATCH_SUBSTR))) {
            nr->list = cur->list;
            list_replace_rcu(&cur->list, &nr->list);
            kf_spin_unlock(&rule_lock);
            kf__call_rcu(&cur->rcu, free_rule_rcu);
            return 0;
        }
    }
    INIT_LIST_HEAD(&nr->list);
    list_add_rcu(&nr->list, &rule_list);
    kf_spin_unlock(&rule_lock);
    return 0;
}

static int del_rule(const char *path) {
    if (!path || !*path) return -EINVAL;
    kf_spin_lock(&rule_lock);
    struct maps_rule *cur;
    list_for_each_entry(cur, &rule_list, list) {
        if (strcmp(cur->match, path) == 0) {
            list_del_rcu(&cur->list);
            kf_spin_unlock(&rule_lock);
            kf__call_rcu(&cur->rcu, free_rule_rcu);
            return 0;
        }
    }
    kf_spin_unlock(&rule_lock);
    return -ENOENT;
}

static void clear_rules(void){
    struct maps_rule* cur;
    kf_spin_lock(&rule_lock);
    while (!list_empty(&rule_list)) {
        cur = list_first_entry(&rule_list, struct maps_rule, list);
        list_del_rcu(&cur->list);
        kf__call_rcu(&cur->rcu, free_rule_rcu);
    }
    kf_spin_unlock(&rule_lock);
}

static void list_rules(void) {
    int i = 0;
    kf_rcu_read_lock();
    struct maps_rule *r;
    list_for_each_entry_rcu(r, &rule_list, list) {
        logkd("[CPAG] #%d match=\"%s\" flags=0x%x newino=%llu newpath=\"%s\" cond_perms=\"%s\" off_mode=%d set_perms=\"%s\" span=%lu",
              i++, r->match, r->flags, r->new_ino,
              r->new_path ? r->new_path : "",
              r->cond_perms[0]? r->cond_perms : "",
              r->cond_off_mode,
              (r->flags & MAPS_ACT_SET_PERMS)? r->set_perms : "",
              (unsigned long)r->set_span);
    }
    kf_rcu_read_unlock();
    if (!i) logkd("[CPAG] rule_list empty");
}

typedef void (*map_show_func_t)(struct seq_file *, struct vm_area_struct *);

static map_show_func_t ori_show_map_vma, backup_show_map_vma;

static hook_err_t hook_err = HOOK_NO_MEM;

static inline void rcu_read_lock_mine(void)
{
    if (kf_rcu_read_lock) kf_rcu_read_lock();
}
static inline void rcu_read_unlock_mine(void)
{
    if (kf_rcu_read_unlock) kf_rcu_read_unlock();
}

/* =========================
   patch_one_maps_line()
   支持 <empty>：匹配“无路径”行
   ========================= */
static bool patch_one_maps_line(struct seq_file *m, char *line, size_t *io_len){
    if (!m || !line || !io_len) return false;
    if (line < m->buf) return false;
    size_t buf_off = (size_t)(line - m->buf);
    if (buf_off >= m->size) return false;

    char *nl = memchr(line, '\n', *io_len);
    if (!nl) return false;
    char *end = nl + 1;

    // 定位五个分段（addr perms offset dev inode | path）
    char *p = line;
    char *sp[5];
    for (int i=0;i<5;i++){
        char *s = memchr(p, ' ', end-p);
        if (!s) return false;
        sp[i] = s;
        p = s+1;
        while (p < end && *p == ' ') p++;
    }

    // 边界
    char *addr_beg = line;

    char *perms_beg = sp[0] + 1; while (perms_beg < end && *perms_beg == ' ') perms_beg++;
    char *perms_end = sp[1];

    char *off_beg = sp[1] + 1;   while (off_beg   < end && *off_beg   == ' ') off_beg++;
    char *off_end = sp[2];

    char *inode_beg = sp[3] + 1; while (inode_beg < end && *inode_beg == ' ') inode_beg++;
    char *inode_end = sp[4];     while (inode_end > inode_beg && *(inode_end-1) == ' ') inode_end--;

    char *path_beg  = sp[4] + 1; while (path_beg  < end && *path_beg  == ' ') path_beg++;

    /* 新增：支持“路径为空”的行 */
    bool is_empty_path = (path_beg >= end || *path_beg == '\n');

    // 解析 perms（当前值）
    char perms_now[5] = {0};
    {
        size_t n = (perms_end > perms_beg) ? (size_t)(perms_end - perms_beg) : 0;
        if (n > 4) n = 4;
        if (n > 0) memcpy(perms_now, perms_beg, n);
        perms_now[4] = 0;
    }

    // offset 是否为 0（仅 '0' 视为 0）
    bool off_is_zero = true;
    {
        char *q = off_beg;
        while (q < off_end && *q == ' ') q++;
        if (q < off_end) {
            for (; q < off_end; ++q){
                if (*q!='0' && *q!=' ' && *q!='\t') { off_is_zero = false; break; }
            }
        }
    }

    // 路径与 (deleted) 判别
    char *path_end = nl;
    size_t base_path_len = 0;
    size_t deleted_len   = 0;
    static const char deleted_suffix[] = " (deleted)";
    if (!is_empty_path) {
        base_path_len = (size_t)(path_end - path_beg);
        if (base_path_len >= sizeof(deleted_suffix)-1){
            char *tail = path_end - (sizeof(deleted_suffix)-1);
            if (tail >= path_beg && !memcmp(tail, deleted_suffix, sizeof(deleted_suffix)-1)){
                base_path_len -= (sizeof(deleted_suffix)-1);
                deleted_len = (sizeof(deleted_suffix)-1);
            }
        }
    }

    // 查规则
    struct maps_rule const *hit = NULL;
    kf_rcu_read_lock();
    struct maps_rule *r;
    list_for_each_entry_rcu(r, &rule_list, list){
        bool path_ok = false;
        if (is_empty_path) {
            // 特殊关键字：<empty>
            path_ok = (r->match_len == 7 && !memcmp(r->match, "<empty>", 7));
        } else if (r->flags & MAPS_MATCH_SUBSTR) {
            if (base_path_len >= r->match_len) {
                const char *hay = path_beg;
                size_t hay_len = base_path_len;
                for (size_t i=0;i + r->match_len <= hay_len; ++i){
                    if (!memcmp(hay+i, r->match, r->match_len)){ path_ok = true; break; }
                }
            }
        } else {
            path_ok = (r->match_len == base_path_len && !memcmp(path_beg, r->match, base_path_len));
        }
        if (!path_ok) continue;

        if (r->cond_perms[0] && strncmp(perms_now, r->cond_perms, 4)!=0) continue;
        if (r->cond_off_mode == 0 && !off_is_zero) continue;
        if (r->cond_off_mode == 1 &&  off_is_zero)  continue;

        hit = r;
        break;
    }
    kf_rcu_read_unlock();
    if (!hit) return false;

    // drop
    if (hit->flags & MAPS_ACT_DROP){
        *io_len = 0;
        return true;
    }

    // inode：保留或替换
    char ino_buf[32];
    int ino_len = 0;
    if (hit->flags & MAPS_ACT_REPL_INO){
        ino_len = kf__scnprintf(ino_buf, sizeof(ino_buf), "%llu", hit->new_ino);
    }else{
        ino_len = (int)(inode_end - inode_beg);
        if (ino_len >= (int)sizeof(ino_buf)) ino_len = (int)sizeof(ino_buf) - 1;
        memcpy(ino_buf, inode_beg, ino_len);
        ino_buf[ino_len] = '\0';
    }

    // path：保留或替换（空路径时 base_path_len=0）
    const char *new_path = (hit->flags & MAPS_ACT_REPL_PATH) ? hit->new_path : NULL;
    size_t new_path_len = new_path ? hit->new_path_len : base_path_len;

    // perms：保留或设置
    const char *out_perms = (hit->flags & MAPS_ACT_SET_PERMS) ? hit->set_perms : NULL;
    size_t out_perms_len  = 4;

    bool keep_deleted = (!is_empty_path) && (hit->flags & MAPS_KEEP_DELETED) && (deleted_len > 0);

    // —— 解析 start，不修改原缓冲 —— //
    unsigned long have_new_range = 0, start_val = 0;
    char new_range[64];
    int  new_range_len = 0;
    size_t range_space_len = 0;

    if (hit->flags & MAPS_ACT_SET_ADDR && hit->set_span > 0) {
        char *sp0 = memchr(addr_beg, ' ', perms_beg - addr_beg);
        if (!sp0) return false;

        char *dash = NULL;
        {
            char *q = addr_beg;
            while (q < sp0) {
                if (*q == '-') { dash = q; break; }
                q++;
            }
        }
        if (!dash) return false;

        {
            unsigned long v = 0;
            char *q = addr_beg;
            while (q < dash) {
                char c = *q++;
                unsigned int d;
                if (c>='0'&&c<='9') d = c-'0';
                else if (c>='a'&&c<='f') d = c-'a'+10;
                else if (c>='A'&&c<='F') d = c-'A'+10;
                else return false;
                v = (v<<4) | d;
            }
            start_val = v;
        }

        unsigned long new_end_ul = start_val + (unsigned long)hit->set_span;
        new_range_len = kf__scnprintf(new_range, sizeof(new_range), "%lx-%lx", start_val, new_end_ul);
        have_new_range = 1;

        range_space_len = (size_t)(perms_beg - sp0);
    }

    size_t prefix0_len = have_new_range ? 0 : (size_t)(perms_beg - addr_beg);
    size_t mid1_len    = (size_t)(inode_beg - perms_end);  // perms..inode 起（含 offset/dev）
    size_t mid2_len    = (size_t)(path_beg  - inode_end);  // inode..path 起
    size_t suffix_len  = 1;

    size_t new_len = 0;
    if (have_new_range) {
        new_len += (size_t)new_range_len + range_space_len;
    } else {
        new_len += prefix0_len;
    }
    new_len += (out_perms ? out_perms_len : (size_t)(perms_end - perms_beg))
             + mid1_len + (size_t)ino_len + mid2_len
             + new_path_len + (keep_deleted ? deleted_len : 0) + suffix_len;

    if (new_len > 4096) return false;

    char tmp[4096];
    size_t off2 = 0;

    if (have_new_range) {
        memcpy(tmp + off2, new_range, new_range_len); off2 += new_range_len;
        char *sp0 = memchr(addr_beg, ' ', perms_beg - addr_beg);
        if (sp0 && range_space_len) {
            memcpy(tmp + off2, sp0, range_space_len); off2 += range_space_len;
        }
    } else {
        memcpy(tmp + off2, addr_beg, prefix0_len); off2 += prefix0_len;
    }

    if (out_perms) {
        memcpy(tmp + off2, out_perms, out_perms_len); off2 += out_perms_len;
    } else {
        size_t n = (size_t)(perms_end - perms_beg);
        memcpy(tmp + off2, perms_beg, n); off2 += n;
    }

    memcpy(tmp + off2, perms_end, mid1_len); off2 += mid1_len;

    memcpy(tmp + off2, ino_buf, ino_len); off2 += ino_len;

    memcpy(tmp + off2, inode_end, mid2_len); off2 += mid2_len;

    if (new_path){
        memcpy(tmp + off2, new_path, new_path_len); off2 += new_path_len;
    }else{
        if (!is_empty_path && base_path_len) {
            memcpy(tmp + off2, path_beg, base_path_len); off2 += base_path_len;
        }
        // 空路径则不输出任何 path 字段
    }

    if (keep_deleted){
        memcpy(tmp + off2, deleted_suffix, deleted_len); off2 += deleted_len;
    }

    tmp[off2++] = '\n';

    memcpy(line, tmp, off2);
    *io_len = off2;
    return true;
}

// ------- UID 过滤 -------
int _target_uid = 0;
static bool is_uid(void)
{
    if (_target_uid <= 0) return false;
    return current_uid() == _target_uid;
}

/* 对一条已经由 show_map 输出的记录做 emaps 改写。
 * hide-so 已经稳定 hook 了 show_map；复用它可以覆盖 Pixel 6 上
 * show_map_vma 不再作为实际 procfs 回调的内核实现。 */
void emaps_patch_show(struct seq_file *m, size_t old)
{
    char *line;
    size_t newlen;

    if (!emaps_ready || !emaps_hooked || !m || !m->buf)
        return;
    if (!emaps_callback_seen) {
        emaps_callback_seen = 1;
        logkd("[CPAG] shared show_map callback active uid=%d", current_uid());
    }
    if (!is_uid() || m->count <= old || old >= m->size)
        return;

    line = m->buf + old;
    newlen = m->count - old;
    bool rewrote = patch_one_maps_line(m, line, &newlen);
    if (rewrote){
        if (!emaps_rewrite_seen) {
            emaps_rewrite_seen = 1;
            logkd("[CPAG] first maps rule rewrite uid=%d", current_uid());
        }
        if (newlen == 0){
            m->count = old; // drop
            return;
        }
        if (old + newlen <= m->size){
            m->count = old + newlen;
        }else{
            m->count = m->size; // 触发 seq 扩容重试
        }
    }
}

static void rep_show_map_vma(struct seq_file *m, struct vm_area_struct *vma){
    size_t old = m->count;
    backup_show_map_vma(m, vma);
    emaps_patch_show(m, old);
}

static map_show_func_t ori_show_map_vma, backup_show_map_vma;

static bool hook_all(void){
    /* 某些 6.1 内核只保留 show_map wrapper；此时由 hide-so 的
     * show_map after 回调调用 emaps_patch_show，不再重复 inline hook。 */
    if (!ori_show_map_vma) {
        logkd("[CPAG] show_map_vma unavailable; use shared show_map callback\n");
        return true;
    }
    struct hook_funcs hooks[] = {
        {ori_show_map_vma, rep_show_map_vma, (void **)&backup_show_map_vma},
    };
    for(size_t i=0;i<ARRAY_SIZE(hooks);i++){
        if (!hooks[i].original){
            logkd("[CPAG] missing symbol for hook %zu\n", i);
            return false;
        }
        hook_err = hook(hooks[i].original, hooks[i].replacement, hooks[i].backup);
        if (hook_err != HOOK_NO_ERR){
            logkd("[CPAG] hook failed at %zu\n", i);
            return false;
        }else{
            logkd("[CPAG] hook success at %zu\n", i);
        }
    }
    return true;
}

static inline bool install_hook(void){
    if (hook_err == HOOK_NO_ERR){
        logkd("[CPAG] hook already installed, skipping...");
        return true;
    }
    if (hook_all()){
        emaps_hooked = 1;
        logkd("[CPAG] hook installed...");
        return true;
    }
    logkd("[CPAG] hook installation failed...");
    return false;
}

static inline bool uninstall_hook(void){
    if (hook_err != HOOK_NO_ERR){
        logkd("[CPAG] not hooked, skipping...");
        return true;
    }
    if (ori_show_map_vma){
        unhook(ori_show_map_vma);
    }
    emaps_hooked = 0;
    hook_err = HOOK_NO_MEM;
    logkd("[CPAG] hook uninstalled...");
    return true;
}

// ------- 模块入口/命令 -------
int emaps_init()
{
    emaps_ready = 0;
    emaps_hooked = 0;
    emaps_callback_seen = 0;
    emaps_rewrite_seen = 0;
    spin_lock_init(&rule_lock);

    kf_rcu_read_lock   = (void *)kallsyms_lookup_name("__rcu_read_lock");
    kf_rcu_read_unlock = (void *)kallsyms_lookup_name("__rcu_read_unlock");
    kf__call_rcu       = (void *)kallsyms_lookup_name("call_rcu");
    kf__synchronize_rcu= (void *)kallsyms_lookup_name("synchronize_rcu");
    kf_spin_unlock     = (void *)kallsyms_lookup_name("_raw_spin_unlock");
    kf_spin_lock       = (void *)kallsyms_lookup_name("_raw_spin_lock");
    kf__kmalloc        = (void *)kallsyms_lookup_name("__kmalloc");
    kf__kfree          = (void *)kallsyms_lookup_name("kfree");
    kf__memset         = (void *)kallsyms_lookup_name("memset");
    kf__kstrdup        = (void *)kallsyms_lookup_name("kstrdup");
    kf_kstrtoint       = (void *)kallsyms_lookup_name("kstrtoint");
    kf__kstrtoull      = (void *)kallsyms_lookup_name("kstrtoull");
    kf__scnprintf      = (void *)kallsyms_lookup_name("scnprintf");

    ori_show_map_vma   = (void *)kallsyms_lookup_name("show_map_vma");
    if (!ori_show_map_vma) {
        logkd("[CPAG] symbol show_map_vma not found; shared show_map path will be used");
    }
    emaps_ready = 1;
    return 0;
}

int emaps_main(struct opts *opts)
{
    int err = 0;
    if (!opts || opts->size < 3){
        return -EINVAL;
    }
    err = kf_kstrtoint(opts->args[1], 10, &_target_uid);
    if (err) _target_uid = -1;

    // 基本控制
    if (strcmp(opts->args[2], "hook") == 0)   { return install_hook() ? 0 : -EINVAL; }
    if (strcmp(opts->args[2], "unhook") == 0) { return uninstall_hook() ? 0 : -EINVAL; }

    // addino <path> <ino>
    if (strcmp(opts->args[2], "addino") == 0 && opts->size >= 5){
        unsigned long long t;
        if (kf__kstrtoull(opts->args[4], 10, &t)) return -EINVAL;
        return add_or_update_rule(opts->args[3], (u64)t, NULL, MAPS_ACT_REPL_INO, NULL);
    }

    // addpath <from> <to> [keep_deleted=1]
    if (strcmp(opts->args[2], "addpath") == 0 && opts->size >= 5){
        u32 f = MAPS_ACT_REPL_PATH;
        if (opts->size >= 6 && strcmp(opts->args[5],"1") == 0) f |= MAPS_KEEP_DELETED;
        return add_or_update_rule(opts->args[3], 0, opts->args[4], f, NULL);
    }

    // addboth <from> <to> <ino> [keep_deleted=1]
    if (strcmp(opts->args[2], "addboth") == 0 && opts->size >= 6){
        unsigned long long t;
        if (kf__kstrtoull(opts->args[5], 10, &t)) return -EINVAL;
        u32 f = MAPS_ACT_REPL_INO | MAPS_ACT_REPL_PATH;
        if (opts->size >= 7 && strcmp(opts->args[6], "1") == 0) f |= MAPS_KEEP_DELETED;
        return add_or_update_rule(opts->args[3], (u64)t, opts->args[4], f, NULL);
    }

    // append <match> <blob>
    if (strcmp(opts->args[2], "append") == 0 && opts->size >= 5) {
        const char *blob = opts->args[4];
        return add_or_update_rule(opts->args[3], 0, NULL, MAPS_ACT_APPEND, blob);
    }

    // drop <path|substr|<empty>> [perms] [0|1]
    if (strcmp(opts->args[2],"drop") == 0 && opts->size >= 4){
        const char *match = opts->args[3];         // 可为 "<empty>" 表示无路径
        const char *lperm = (opts->size >= 5 && strlen(opts->args[4])>=4) ? opts->args[4] : NULL;
        int off_mode = -1;
        if (opts->size >= 6 && (opts->args[5][0]=='0' || opts->args[5][0]=='1')){
            off_mode = (opts->args[5][0]=='0') ? 0 : 1;
        }
        return add_or_update_rule_ex(match, 0, NULL,
                                    MAPS_ACT_DROP,
                                    NULL,
                                    lperm, off_mode,
                                    NULL, 0UL);
    }

    // addpathrxp <from> <to> <left_perms> [0|1]
    if (strcmp(opts->args[2], "addpathrxp") == 0 && opts->size >= 6){
        const char *from  = opts->args[3];
        const char *to    = opts->args[4];
        const char *lperm = opts->args[5];
        int off_mode = -1;
        if (opts->size >= 7 && (opts->args[6][0]=='0' || opts->args[6][0]=='1')){
            off_mode = (opts->args[6][0]=='0') ? 0 : 1;
        }
        return add_or_update_rule_ex(from, 0, to,
                                    MAPS_ACT_REPL_PATH | MAPS_ACT_SET_PERMS,
                                    NULL,
                                    lperm, off_mode,
                                    "r-xp", 0UL);
    }

    // addpathaddr <path|substr> <perms> <off0|1> <span> [newino]
    if (strcmp(opts->args[2], "addpathaddr") == 0 && opts->size >= 7){
        const char *match = opts->args[3];
        const char *lperm = opts->args[4];
        int off_mode = (opts->args[5][0] == '0') ? 0 : 1;
        unsigned long span = 0;
        if (kf__kstrtoull(opts->args[6], 10, &span)) return -EINVAL;

        u32 flags = MAPS_ACT_SET_ADDR | MAPS_ACT_SET_PERMS;   // 保持 perms 为 lperm
        u64 ino = 0;
        if (opts->size >= 8) {
            unsigned long long tmp=0;
            if (!kf__kstrtoull(opts->args[7], 10, &tmp)) {
                ino = (u64)tmp;
                flags |= MAPS_ACT_REPL_INO;
            }
        }
        return add_or_update_rule_ex(match, ino, NULL,
                                    flags,
                                    NULL,
                                    lperm, off_mode,
                                    lperm /*set_perms 与条件同*/, span);
    }

    if (strcmp(opts->args[2], "del") == 0 && opts->size >= 4){
        return del_rule(opts->args[3]);
    }
    if (strcmp(opts->args[2], "clear") == 0){
        clear_rules();
        return 0;
    }
    if (strcmp(opts->args[2], "list") == 0){
        list_rules();
        return 0;
    }
    return -EINVAL;
}

int emaps_test(struct opts *opts){
    return 0;
}

void emaps_exit()
{
    emaps_ready = 0;
    emaps_hooked = 0;
    uninstall_hook();
    clear_rules();
    logkd("[CPAG] emap_exit");
}
