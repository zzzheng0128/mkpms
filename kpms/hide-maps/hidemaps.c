/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm-hide-so v1.2.0 - Hide selected shared object mappings and threads from procfs
 *
 * Recovered from the deployed hide-so.kpm binary (DWARF + Hex-Rays, 2026-09).
 * Original build: GNU C17 13.3.0 -Os -g, src: kpms/hide-maps/hidemaps.c (~1450 lines).
 *
 * Hiding model:
 *   - VMAs whose /proc/<pid>/maps line contains a hidden token (default "wwb_")
 *     are removed from maps/smaps/numa_maps output, and their address ranges are
 *     remembered so the matching map_files dentries and fill_cache entries can
 *     be suppressed as well.
 *   - Threads whose comm starts with thread_hide_prefix ("wwb-") are hidden from
 *     /proc/<pid>/task, comm, cgroup lists, and the thread counts shown in
 *     status/stat/sched are rewritten to the visible count.
 *   - "[anon:stack_and_tls:<pid>]" VMAs of hidden threads are dropped, and the
 *     "[anon:thread signal stack]" VMA immediately following each of them is
 *     dropped via the pending_signal_stack_hides counter.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <asm/current.h>
#include <hook.h>
#include "../mkpm/compat/hook_lifecycle.h"
#include "../common/kpm_demo_helpers.h"

/* emaps 与 hide-so 共用 show_map 的 after 回调，覆盖 Pixel 6 的
 * show_map_vma 未实际进入 procfs 渲染链路的情况。 */
struct seq_file;
extern void emaps_patch_show(struct seq_file *m, size_t old);

#ifndef MKPM_MERGED
KPM_MODULE_INFO("kpm-hide-so", "1.2.0", "GPL v2", "wwb",
                "Hide selected shared object mappings and threads from procfs");
#endif

/* ---------------------------------------------------------------- views --- */

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct hm_qstr_view {
    union {
        uint64_t hash_len;
        struct {
            uint32_t hash;
            uint32_t len;
        };
    };
    const unsigned char *name;
};

struct hm_dentry_view {
    char pad0[24];
    struct dentry *d_parent;
    struct hm_qstr_view d_name;
};

typedef struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
} seq_file;

struct hm_range {
    unsigned long start;
    unsigned long end;
};

struct hm_map_state {
    seq_file *m;
    int pending_signal_stack_hides;
    int skipping_smap_block;
};

struct hm_getattr_state {
    struct task_struct *reader;
    struct pid_namespace *ns;
    pid_t tgid;
    int active;
};

struct hm_kstat {
    uint32_t result_mask;
    unsigned short mode;
    unsigned int nlink;
};

/* -------------------------------------------------------------- globals --- */

static void *hook_show_map;
static void *hook_show_smap;
static void *hook_show_numa_map;
static void *hook_proc_fill_cache;
static void *hook_proc_pid_instantiate;
static void *hook_proc_task_instantiate;
static void *hook_proc_map_files_lookup;
static void *hook_map_files_get_link;
static void *hook_cgroup_procs_show;
static void *hook_cgroup_pidlist_show;
static void *hook_comm_show;
static void *hook_proc_pid_status;
static void *hook_proc_tgid_stat;
static void *hook_proc_tid_stat;
static void *hook_do_task_stat;
static void *hook_proc_task_getattr;
static void *hook_proc_sched_show_task;
static void *hook_proc_hidden_single_show[20];
static void *sym_proc_map_files_instantiate;
static void *sym_proc_task_instantiate;

static char *(*kfn_dentry_path)(struct dentry *, char *, int);
static pid_t (*kfn_task_pid_nr_ns)(struct task_struct *, enum pid_type, struct pid_namespace *);
static struct pid *(*kfn_find_ge_pid)(int, struct pid_namespace *);
static struct task_struct *(*kfn_pid_task)(struct pid *, enum pid_type);
static pid_t (*kfn_pid_nr_ns)(struct pid *, struct pid_namespace *);
static struct task_struct *(*kfn_find_task_by_vpid)(pid_t);
static struct pid_namespace *(*kfn_task_active_pid_ns)(struct task_struct *);

static struct hm_range hidden_ranges[256];
static int hidden_range_pos;
static int hidden_range_count;
static struct hm_map_state map_states[32];
static int map_state_pos;
static struct hm_getattr_state getattr_states[16];
static int getattr_state_pos;

/* ----------------------------------------------------- feature switches --- */
/* all default ON (see hide_so_init); controlled via ctl0 */
static int hm_enabled = 1;      /* master switch */
static int hm_hide_maps = 1;    /* maps/smaps/numa_maps/map_files hiding */
static int hm_hide_threads = 1; /* thread hiding + thread count rewriting */
static int hm_maps_callback_seen;

#define HM_MAX_TOKENS 8
#define HM_TOKEN_LEN 32
static char hidden_token_storage[HM_MAX_TOKENS][HM_TOKEN_LEN];
static const char *hidden_tokens[HM_MAX_TOKENS + 1]; /* NULL-terminated */
static int hidden_token_count;

static char thread_hide_prefix[16];
static int thread_hide_prefix_len;

static const char *proc_hidden_single_show_symbols[] = {
    "proc_pid_personality",
    "proc_pid_limits",
    "proc_pid_syscall",
    "proc_pid_statm",
    "proc_pid_wchan",
    "proc_pid_stack",
    "proc_pid_schedstat",
    "proc_cpuset_show",
    "proc_cgroup_show",
    "proc_resctrl_show",
    "proc_oom_score",
    "proc_tgid_io_accounting",
    "proc_tid_io_accounting",
    "proc_pid_patch_state",
    "proc_time_in_state_show",
    "proc_stack_depth",
    "proc_pid_arch_status",
    "proc_pid_seccomp_cache",
    "proc_pid_ksm_merging_pages",
    "proc_pid_ksm_stat",
};

/* -------------------------------------------------------- token helpers --- */

static int contains_token(const char *buf, size_t len, const char *token)
{
    size_t tlen, limit, i;

    if (!token)
        return 0;
    tlen = strlen(token);
    if (len <= tlen - 1)
        return 0;
    limit = len - tlen;
    for (i = 0; i <= limit; i++) {
        if (!memcmp(buf + i, token, tlen))
            return 1;
    }
    return 0;
}

static int contains_hidden_token(const char *buf, size_t len)
{
    int i;

    for (i = 0; hidden_tokens[i]; i++) {
        if (contains_token(buf, len, hidden_tokens[i]))
            return 1;
    }
    return 0;
}

static int find_token_pos(const char *buf, size_t len, const char *token, size_t *pos_out)
{
    size_t tlen, limit, i;

    if (!token)
        return 0;
    tlen = strlen(token);
    if (len < tlen)
        return 0;
    limit = len - tlen;
    for (i = 0; i <= limit; i++) {
        if (!memcmp(buf + i, token, tlen)) {
            *pos_out = i;
            return 1;
        }
    }
    return 0;
}

/* --------------------------------------------------------- line parsing --- */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex_field(const char *s, size_t len, size_t *pos, unsigned long *value)
{
    size_t i = *pos;
    unsigned long v = 0;

    for (; i < len; i++) {
        int d = hex_val(s[i]);
        if (d < 0)
            break;
        v = (v << 4) | (unsigned long)d;
    }
    if (i == *pos)
        return 0;
    *value = v;
    *pos = i;
    return 1;
}

/* "start-end", must consume the whole string */
static int parse_range_name(const char *s, size_t len, unsigned long *start, unsigned long *end)
{
    size_t pos = 0;

    if (!parse_hex_field(s, len, &pos, start))
        return 0;
    if (pos >= len || s[pos] != '-')
        return 0;
    pos++;
    if (!parse_hex_field(s, len, &pos, end))
        return 0;
    if (pos != len || *end <= *start)
        return 0;
    return 1;
}

/* "start-end" at the head of a maps line; trailing text allowed */
static int parse_line_range(const char *s, size_t len, unsigned long *start, unsigned long *end)
{
    size_t pos = 0;

    if (!parse_hex_field(s, len, &pos, start))
        return 0;
    if (pos >= len || s[pos] != '-')
        return 0;
    pos++;
    if (!parse_hex_field(s, len, &pos, end))
        return 0;
    return *end > *start;
}

static const char *basename_ptr(const char *path, size_t len, size_t *name_len)
{
    size_t n = len;
    size_t i;

    if (!path || !len)
        return 0;
    while (n && path[n - 1] == '/') {
        n--;
        if (!n)
            return 0;
    }
    for (i = n; i; i--) {
        if (path[i - 1] == '/') {
            *name_len = n - i;
            return path + i;
        }
    }
    *name_len = n;
    return path;
}

/* ------------------------------------------------------ hidden range set --- */

static void remember_hidden_range(unsigned long start, unsigned long end)
{
    int i;

    if (!start || start >= end)
        return;
    for (i = 0; i < hidden_range_count; i++) {
        if (hidden_ranges[i].start == start && hidden_ranges[i].end == end)
            return;
    }
    hidden_ranges[hidden_range_pos].start = start;
    hidden_ranges[hidden_range_pos].end = end;
    hidden_range_pos = (hidden_range_pos + 1) % 256;
    if (hidden_range_count != 256)
        hidden_range_count++;
}

static int hidden_range_match(unsigned long start, unsigned long end)
{
    int i;

    for (i = 0; i < hidden_range_count; i++) {
        if (hidden_ranges[i].start == start && hidden_ranges[i].end == end)
            return 1;
    }
    return 0;
}

static int hidden_range_name(const char *name, size_t len)
{
    unsigned long start, end;

    if (!parse_range_name(name, len, &start, &end))
        return 0;
    return hidden_range_match(start, end);
}

static int hidden_range_path(const char *path, size_t len)
{
    size_t name_len = 0;
    const char *name = basename_ptr(path, len, &name_len);

    if (!name || !name_len)
        return 0;
    return hidden_range_name(name, name_len);
}

/* ------------------------------------------------------- thread helpers --- */

static int is_hidden_thread(struct task_struct *task)
{
    const char *comm;

    if (!hm_enabled || !hm_hide_threads)
        return 0;
    if (thread_hide_prefix_len <= 0)
        return 0;
    if (!task)
        return 0;
    if (task_struct_offset.comm_offset < 0)
        return 0;
    comm = (const char *)task + task_struct_offset.comm_offset;
    if (!comm)
        return 0;
    return strncmp(comm, thread_hide_prefix, thread_hide_prefix_len) == 0;
}

static pid_t task_pid_value_ns(struct task_struct *task, enum pid_type type, struct pid_namespace *ns)
{
    if (!task || !kfn_task_pid_nr_ns)
        return 0;
    return kfn_task_pid_nr_ns(task, type, ns);
}

static int count_threads_for_tgid(struct pid_namespace *ns, pid_t tgid, int *total_out, int *hidden_out)
{
    int total = 0;
    int hidden = 0;
    int guard = 65537;
    pid_t next = 1;
    struct pid *p;

    *total_out = 0;
    *hidden_out = 0;
    if (!tgid)
        return 0;
    if (!kfn_find_ge_pid || !kfn_pid_task || !kfn_pid_nr_ns)
        return 0;
    p = kfn_find_ge_pid(next, ns);
    while (p) {
        pid_t nr;
        struct task_struct *task;

        if (!--guard)
            break;
        nr = kfn_pid_nr_ns(p, ns);
        if (next > nr)
            break;
        task = kfn_pid_task(p, PIDTYPE_PID);
        if (task) {
            if (task_pid_value_ns(task, PIDTYPE_TGID, ns) == tgid) {
                total++;
                if (is_hidden_thread(task))
                    hidden++;
            }
        }
        next = nr + 1;
        p = kfn_find_ge_pid(next, ns);
    }
    *total_out = total;
    *hidden_out = hidden;
    return total > 0;
}

static int visible_threads_for_tgid(struct pid_namespace *ns, pid_t tgid, int *visible_out)
{
    int total, hidden, visible;

    if (!count_threads_for_tgid(ns, tgid, &total, &hidden))
        return 0;
    visible = total - hidden;
    if (visible <= 0)
        visible = 1;
    *visible_out = visible;
    return 1;
}

/* ------------------------------------------------------ getattr tracking --- */

static struct hm_getattr_state *find_getattr_state(struct task_struct *reader)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (getattr_states[i].active && getattr_states[i].reader == reader)
            return &getattr_states[i];
    }
    return 0;
}

static struct hm_getattr_state *start_getattr_state(void)
{
    struct task_struct *reader = get_current();
    struct hm_getattr_state *state;

    if (!reader)
        return 0;
    state = find_getattr_state(reader);
    if (!state) {
        getattr_state_pos = (getattr_state_pos + 1) % 16;
        state = &getattr_states[getattr_state_pos];
    }
    return state;
}

static void clear_getattr_state(struct hm_getattr_state *state)
{
    state->reader = 0;
    state->ns = 0;
    state->tgid = 0;
    state->active = 0;
}

/* --------------------------------------------------------- map state slot --- */

static struct hm_map_state *get_map_state(seq_file *m)
{
    int i;
    int empty = -1;
    struct hm_map_state *state;

    for (i = 0; i < 32; i++) {
        if (map_states[i].m == m)
            return &map_states[i];
        if (!map_states[i].m && empty < 0)
            empty = i;
    }
    if (empty < 0) {
        map_state_pos = (map_state_pos + 1) % 32;
        empty = map_state_pos;
    }
    state = &map_states[empty];
    state->m = m;
    state->pending_signal_stack_hides = 0;
    state->skipping_smap_block = 0;
    return state;
}

/* ---------------------------------------------------- pid/name parsing --- */

/* parse a decimal number that spans [pos, len) exactly; value must be > 0 */
static int parse_decimal_tid(const char *buf, size_t len, size_t pos, pid_t *tid_out)
{
    pid_t v = 0;
    size_t i = pos;

    while (i < len) {
        unsigned char c = (unsigned char)buf[i];
        if (c < '0' || c > '9')
            break;
        if ((unsigned int)v > 0x19999999u)
            return 0;
        v = v * 10 + (c - '0');
        i++;
    }
    if (!v || i != len || v <= 0)
        return 0;
    *tid_out = v;
    return 1;
}

/* parse a decimal pid immediately followed by ']' */
static int parse_decimal_pid_name(const char *buf, size_t len, pid_t *pid_out)
{
    pid_t v = 0;
    size_t i = 0;
    int ndigits = 0;

    while (i < len) {
        unsigned char c = (unsigned char)buf[i];
        if (c < '0' || c > '9')
            break;
        if ((unsigned int)v > 0x19999999u)
            return 0;
        v = v * 10 + (c - '0');
        i++;
        ndigits++;
    }
    if (!ndigits || i >= len || buf[i] != ']' || v <= 0)
        return 0;
    *pid_out = v;
    return 1;
}

/* "[anon:stack_and_tls:<pid>]" belonging to a hidden thread */
static int line_has_hidden_stack_and_tls(const char *buf, size_t len)
{
    size_t pos;
    pid_t pid;
    struct task_struct *task;

    if (!kfn_find_task_by_vpid)
        return 0;
    if (!find_token_pos(buf, len, "[anon:stack_and_tls:", &pos))
        return 0;
    pos += strlen("[anon:stack_and_tls:");
    if (pos >= len)
        return 0;
    if (!parse_decimal_pid_name(buf + pos, len - pos, &pid))
        return 0;
    task = kfn_find_task_by_vpid(pid);
    return is_hidden_thread(task);
}

static int line_has_thread_signal_stack(const char *buf, size_t len)
{
    return contains_token(buf, len, "[anon:thread signal stack]");
}

/* ----------------------------------------------------- number rewriting --- */

static int append_uint(char *buf, int value)
{
    char tmp[16];
    int n = 0;
    int prev;
    int i;

    if (value <= 0) {
        buf[0] = '0';
        return 1;
    }
    do {
        prev = value;
        tmp[n] = (char)('0' + value % 10);
        value /= 10;
        n++;
    } while (prev > 9 && n <= 15);
    for (i = n - 1; i >= 0; i--)
        *buf++ = tmp[i];
    return n;
}

static size_t first_line_len(const char *buf, size_t len)
{
    size_t n = 0;

    while (n < len && buf[n] != '\n')
        n++;
    return n;
}

/* overlapping-safe forward copy, dst must be below src */
static void move_left(char *dst, const char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dst[i] = src[i];
}

/* replace digits in [tok_start, tok_end) with new_value; only ever shrinks */
static int rewrite_number_token(seq_file *m, size_t tok_start, size_t tok_end, int new_value)
{
    char tmp[16];
    int n;
    size_t old_len = tok_end - tok_start;

    n = append_uint(tmp, new_value);
    if (old_len < (size_t)n)
        return 0;
    memcpy(m->buf + tok_start, tmp, n);
    if (old_len != (size_t)n) {
        move_left(m->buf + tok_start + n, m->buf + tok_end, m->count - tok_end);
        m->count += tok_start + n - tok_end;
    }
    return 1;
}

/* rewrite the number after "Threads:\t" in /proc/<pid>/status output */
static void rewrite_threads_line_value(seq_file *m, size_t start, int new_value)
{
    size_t count, i, j;

    if (!m || !m->buf || start == (size_t)-1)
        return;
    count = m->count;
    if (start >= count || count > m->size)
        return;
    for (i = start + 9; i < count; i++) {
        if (memcmp(m->buf + i - 9, "Threads:\t", 9))
            continue;
        for (j = i; j < count; j++) {
            unsigned char c = (unsigned char)m->buf[j];
            if (c < '0' || c > '9')
                break;
        }
        if (i == j)
            return;
        rewrite_number_token(m, i, j, new_value);
        return;
    }
}

/* rewrite the number after "#threads: " in /proc/<pid>/sched output */
static void rewrite_sched_threads_line(seq_file *m, size_t start, int new_value)
{
    size_t count, i, j;

    if (!m || !m->buf || new_value <= 0 || start == (size_t)-1)
        return;
    count = m->count;
    if (start >= count || count > m->size)
        return;
    for (i = start + 10; i < count; i++) {
        const char *p = m->buf + i - 10;
        if (*p == '\n')
            break;
        if (memcmp(p, "#threads: ", 10))
            continue;
        for (j = i; j < count; j++) {
            unsigned char c = (unsigned char)m->buf[j];
            if (c < '0' || c > '9')
                break;
        }
        if (i == j)
            return;
        rewrite_number_token(m, i, j, new_value);
        return;
    }
}

/* rewrite num_threads (field 20) in /proc/<pid>/stat output */
static void rewrite_stat_threads_field_value(seq_file *m, size_t start, int new_value)
{
    char *buf;
    size_t count, pos, i, tok_start;
    int field;

    if (!m)
        return;
    buf = m->buf;
    if (!buf)
        return;
    if (new_value <= 0 || start == (size_t)-1)
        return;
    count = m->count;
    if (start >= count || count > m->size)
        return;
    /* locate ") " closing the comm field, scanning back from the end */
    pos = count;
    for (;;) {
        if (buf[pos - 1] == ')' && pos < count && buf[pos] == ' ')
            break;
        if (--pos == start)
            return;
    }
    i = pos + 1;
    if (i >= count)
        return;
    /* num_threads is the 18th field after ") " (fields 3..20) */
    field = 18;
    do {
        while (buf[i] == ' ') {
            if (++i == count)
                return;
        }
        if (buf[i] == '\n')
            break;
        tok_start = i;
        while (i < count && buf[i] != ' ' && buf[i] != '\n')
            i++;
        if (!--field) {
            if (tok_start < i && i <= count)
                rewrite_number_token(m, tok_start, i, new_value);
            return;
        }
    } while (i < count);
}

/* ------------------------------------------------------ maps filtering --- */

/*
 * > 0: header of a hidden VMA (remember the range, drop the line)
 *   0: ordinary header line, keep it
 * < 0: not a maps header line at all
 */
static int classify_map_header(struct hm_map_state *state, const char *buf, size_t len,
                               unsigned long *vm_start, unsigned long *vm_end)
{
    size_t line_len = first_line_len(buf, len);

    if (!parse_line_range(buf, line_len, vm_start, vm_end))
        return -1;
    if (contains_hidden_token(buf, line_len))
        return 1;
    if (line_has_hidden_stack_and_tls(buf, line_len)) {
        if (!state)
            return 1;
        state->pending_signal_stack_hides++;
        return 1;
    }
    if (line_has_thread_signal_stack(buf, line_len)) {
        if (!state)
            return 0;
        if (state->pending_signal_stack_hides <= 0)
            return 0;
        state->pending_signal_stack_hides--;
        return 1;
    }
    return 0;
}

static void filter_map_block(seq_file *m, size_t start)
{
    struct hm_map_state *state;
    unsigned long vm_start, vm_end;
    size_t count;

    if (!hm_enabled || !hm_hide_maps)
        return;
    if (!m || start == (size_t)-1)
        return;
    count = m->count;
    if (!m->buf)
        return;
    if (start >= count || count > m->size || count - start > 0x4000)
        return;
    state = get_map_state(m);
    if (classify_map_header(state, m->buf + start, count - start, &vm_start, &vm_end) > 0) {
        remember_hidden_range(vm_start, vm_end);
        m->count = start;
    }
}

static void filter_smap_block(seq_file *m, size_t start)
{
    struct hm_map_state *state;
    unsigned long vm_start, vm_end;
    size_t count;
    int cls;

    if (!hm_enabled || !hm_hide_maps)
        return;
    if (!m || start == (size_t)-1)
        return;
    count = m->count;
    if (!m->buf)
        return;
    if (start >= count || count > m->size)
        return;
    state = get_map_state(m);
    if (!state)
        return;
    cls = classify_map_header(state, m->buf + start, count - start, &vm_start, &vm_end);
    if (state->skipping_smap_block) {
        /* still inside a dropped smaps block: keep swallowing lines */
        if (cls < 0) {
            m->count = start;
            return;
        }
        state->skipping_smap_block = 0;
    }
    if (cls > 0) {
        remember_hidden_range(vm_start, vm_end);
        state->skipping_smap_block = 1;
        m->count = start;
    }
}

/* ------------------------------------------------------------ hook cbs --- */

static void seq_show_before(hook_fargs2_t *args, void *udata)
{
    seq_file *m = (seq_file *)args->arg0;

    args->local.data0 = m ? m->count : (uint64_t)-1;
}

static void seq_arg2_before(hook_fargs3_t *args, void *udata)
{
    seq_file *m = (seq_file *)args->arg2;

    args->local.data0 = m ? m->count : (uint64_t)-1;
}

static void seq_show_after(hook_fargs2_t *args, void *udata)
{
    if (!hm_maps_callback_seen) {
        hm_maps_callback_seen = 1;
        pr_info("hide-so: show_map callback active\n");
    }
    filter_map_block((seq_file *)args->arg0, args->local.data0);
    emaps_patch_show((struct seq_file *)args->arg0, args->local.data0);
}

static void seq_smap_after(hook_fargs2_t *args, void *udata)
{
    filter_smap_block((seq_file *)args->arg0, args->local.data0);
}

static void cgroup_procs_show_after(hook_fargs2_t *args, void *udata)
{
    seq_file *m = (seq_file *)args->arg0;
    struct task_struct *task = (struct task_struct *)args->arg1;

    if (!m || args->local.data0 == (uint64_t)-1)
        return;
    if (is_hidden_thread(task))
        m->count = args->local.data0;
}

static void cgroup_pidlist_show_after(hook_fargs2_t *args, void *udata)
{
    seq_file *m = (seq_file *)args->arg0;
    pid_t *pidp;
    struct task_struct *task;

    if (!m || args->local.data0 == (uint64_t)-1)
        return;
    pidp = (pid_t *)args->arg1;
    if (!pidp || !kfn_find_task_by_vpid)
        return;
    if (*pidp <= 0)
        return;
    task = kfn_find_task_by_vpid(*pidp);
    if (is_hidden_thread(task))
        m->count = args->local.data0;
}

static void proc_thread_instantiate_before(hook_fargs3_t *args, void *udata)
{
    if (is_hidden_thread((struct task_struct *)args->arg1)) {
        args->ret = -2; /* -ENOENT: pretend the task dir entry does not exist */
        args->skip_origin = 1;
    }
}

static int hide_hidden_task_seq(struct task_struct *task, seq_file *m, size_t start)
{
    if (!m || start == (size_t)-1)
        return 0;
    if (!is_hidden_thread(task))
        return 0;
    m->count = start;
    return 1;
}

static void proc_hidden_single_show_after(hook_fargs4_t *args, void *udata)
{
    hide_hidden_task_seq((struct task_struct *)args->arg3, (seq_file *)args->arg0, args->local.data0);
}

static void comm_show_after(hook_fargs2_t *args, void *udata)
{
    seq_file *m = (seq_file *)args->arg0;
    size_t start = args->local.data0;
    size_t count;

    if (!m || !m->buf || start == (size_t)-1)
        return;
    if (thread_hide_prefix_len <= 0)
        return;
    count = m->count;
    if (count > start && count <= m->size && count - start >= (size_t)thread_hide_prefix_len &&
        !memcmp(m->buf + start, thread_hide_prefix, thread_hide_prefix_len))
        m->count = start;
}

static void proc_pid_status_after(hook_fargs4_t *args, void *udata)
{
    struct pid_namespace *ns = (struct pid_namespace *)args->arg1;
    struct task_struct *task = (struct task_struct *)args->arg3;
    pid_t tgid;
    int total, hidden, visible;

    if (hide_hidden_task_seq(task, (seq_file *)args->arg0, args->local.data0))
        return;
    tgid = task_pid_value_ns(task, PIDTYPE_TGID, ns);
    if (!count_threads_for_tgid(ns, tgid, &total, &hidden))
        return;
    visible = total - hidden;
    if (visible <= 0)
        visible = 1;
    rewrite_threads_line_value((seq_file *)args->arg0, args->local.data0, visible);
}

static void proc_pid_stat_after(hook_fargs4_t *args, void *udata)
{
    struct pid_namespace *ns = (struct pid_namespace *)args->arg1;
    struct task_struct *task = (struct task_struct *)args->arg3;
    pid_t tgid;
    int visible;

    if (hide_hidden_task_seq(task, (seq_file *)args->arg0, args->local.data0))
        return;
    tgid = task_pid_value_ns(task, PIDTYPE_TGID, ns);
    if (visible_threads_for_tgid(ns, tgid, &visible))
        rewrite_stat_threads_field_value((seq_file *)args->arg0, args->local.data0, visible);
}

static void do_task_stat_after(hook_fargs5_t *args, void *udata)
{
    struct pid_namespace *ns = (struct pid_namespace *)args->arg1;
    struct task_struct *task = (struct task_struct *)args->arg3;
    pid_t tgid;
    int visible;

    if (hide_hidden_task_seq(task, (seq_file *)args->arg0, args->local.data0))
        return;
    tgid = task_pid_value_ns(task, PIDTYPE_TGID, ns);
    if (visible_threads_for_tgid(ns, tgid, &visible))
        rewrite_stat_threads_field_value((seq_file *)args->arg0, args->local.data0, visible);
}

static void proc_sched_show_task_after(hook_fargs3_t *args, void *udata)
{
    struct task_struct *task = (struct task_struct *)args->arg0;
    struct pid_namespace *ns = (struct pid_namespace *)args->arg1;
    seq_file *m = (seq_file *)args->arg2;
    pid_t tgid;
    int visible;

    if (hide_hidden_task_seq(task, m, args->local.data0))
        return;
    tgid = task_pid_value_ns(task, PIDTYPE_TGID, ns);
    if (visible_threads_for_tgid(ns, tgid, &visible))
        rewrite_sched_threads_line(m, args->local.data0, visible);
}

static void proc_task_getattr_before(hook_fargs5_t *args, void *udata)
{
    struct path *path = (struct path *)args->arg1;
    struct hm_dentry_view *dentry, *parent;
    struct pid_namespace *ns;
    pid_t tgid = 0;
    struct hm_getattr_state *state;

    if (!path)
        return;
    dentry = (struct hm_dentry_view *)path->dentry;
    if (!dentry)
        return;
    if (!kfn_task_active_pid_ns)
        return;
    if (dentry->d_name.len != 4 || memcmp(dentry->d_name.name, "task", 4))
        return;
    ns = kfn_task_active_pid_ns(get_current());
    if (!ns)
        return;
    parent = (struct hm_dentry_view *)dentry->d_parent;
    if (parent && parent->d_name.name && parent->d_name.len)
        parse_decimal_tid((const char *)parent->d_name.name, parent->d_name.len, 0, &tgid);
    if (tgid <= 0) {
        tgid = task_pid_value_ns(get_current(), PIDTYPE_TGID, ns);
        if (tgid <= 0)
            return;
    }
    state = start_getattr_state();
    if (!state)
        return;
    state->reader = get_current();
    state->ns = ns;
    state->tgid = tgid;
    state->active = 1;
}

static void proc_task_getattr_after(hook_fargs5_t *args, void *udata)
{
    struct hm_kstat *stat = (struct hm_kstat *)args->arg2;
    struct hm_getattr_state *state;
    struct pid_namespace *ns;
    pid_t tgid;
    int total, hidden;

    state = find_getattr_state(get_current());
    if (args->ret || !stat || !state) {
        if (state)
            clear_getattr_state(state);
        return;
    }
    if (stat->nlink <= 2 || !state->ns || state->tgid <= 0) {
        clear_getattr_state(state);
        return;
    }
    ns = state->ns;
    tgid = state->tgid;
    clear_getattr_state(state);
    if (count_threads_for_tgid(ns, tgid, &total, &hidden) && hidden > 0) {
        /* task dir nlink is nr_threads + 2; drop the hidden ones */
        if (total == (int)stat->nlink - 2)
            stat->nlink -= hidden;
    }
}

static void proc_fill_cache_before(hook_fargs7_t *args, void *udata)
{
    const char *name = (const char *)args->arg2;
    unsigned int len = (unsigned int)args->arg3;
    void *instantiate = (void *)args->arg4;
    struct task_struct *task = (struct task_struct *)args->arg5;

    if (!name || !len)
        return;
    if ((hm_enabled && hm_hide_maps && sym_proc_map_files_instantiate &&
         instantiate == sym_proc_map_files_instantiate && hidden_range_name(name, len)) ||
        (sym_proc_task_instantiate && instantiate == sym_proc_task_instantiate &&
         is_hidden_thread(task))) {
        args->skip_origin = 1;
        args->ret = 1; /* skip this dcache entry */
    }
}

static void proc_map_files_lookup_before(hook_fargs3_t *args, void *udata)
{
    struct dentry *dentry = (struct dentry *)args->arg1;
    char buf[512];
    char *path;
    size_t len;

    if (!dentry || !kfn_dentry_path)
        return;
    if (!hm_enabled || !hm_hide_maps)
        return;
    path = kfn_dentry_path(dentry, buf, sizeof(buf));
    if ((unsigned long)path > 0xfffffffffffff000UL) /* IS_ERR */
        return;
    len = strlen(path);
    if (hidden_range_path(path, len)) {
        args->ret = -2; /* -ENOENT */
        args->skip_origin = 1;
    }
}

static void map_files_get_link_before(hook_fargs2_t *args, void *udata)
{
    struct dentry *dentry = (struct dentry *)args->arg0;
    char buf[512];
    char *path;
    size_t len;

    if (!dentry || !kfn_dentry_path)
        return;
    if (!hm_enabled || !hm_hide_maps)
        return;
    path = kfn_dentry_path(dentry, buf, sizeof(buf));
    if ((unsigned long)path > 0xfffffffffffff000UL) /* IS_ERR */
        return;
    len = strlen(path);
    if (hidden_range_path(path, len)) {
        args->ret = -2; /* -ENOENT */
        args->skip_origin = 1;
    }
}

/* -------------------------------------------------------- hook install --- */

static void unhook_all(void)
{
    int i;

    for (i = 0; i < 20; i++) {
        if (hook_proc_hidden_single_show[i]) {
            mkpm_unwrap_for_exit(hook_proc_hidden_single_show[i], seq_show_before, proc_hidden_single_show_after);
            hook_proc_hidden_single_show[i] = 0;
        }
    }
    if (hook_proc_tid_stat) {
        mkpm_unwrap_for_exit(hook_proc_tid_stat, seq_show_before, proc_pid_stat_after);
        hook_proc_tid_stat = 0;
    }
    if (hook_proc_tgid_stat) {
        mkpm_unwrap_for_exit(hook_proc_tgid_stat, seq_show_before, proc_pid_stat_after);
        hook_proc_tgid_stat = 0;
    }
    if (hook_do_task_stat) {
        mkpm_unwrap_for_exit(hook_do_task_stat, seq_show_before, do_task_stat_after);
        hook_do_task_stat = 0;
    }
    if (hook_proc_sched_show_task) {
        mkpm_unwrap_for_exit(hook_proc_sched_show_task, seq_arg2_before, proc_sched_show_task_after);
        hook_proc_sched_show_task = 0;
    }
    if (hook_proc_task_getattr) {
        mkpm_unwrap_for_exit(hook_proc_task_getattr, proc_task_getattr_before, proc_task_getattr_after);
        hook_proc_task_getattr = 0;
    }
    if (hook_proc_pid_status) {
        mkpm_unwrap_for_exit(hook_proc_pid_status, seq_show_before, proc_pid_status_after);
        hook_proc_pid_status = 0;
    }
    if (hook_cgroup_pidlist_show) {
        mkpm_unwrap_for_exit(hook_cgroup_pidlist_show, seq_show_before, cgroup_pidlist_show_after);
        hook_cgroup_pidlist_show = 0;
    }
    if (hook_cgroup_procs_show) {
        mkpm_unwrap_for_exit(hook_cgroup_procs_show, seq_show_before, cgroup_procs_show_after);
        hook_cgroup_procs_show = 0;
    }
    if (hook_comm_show) {
        mkpm_unwrap_for_exit(hook_comm_show, seq_show_before, comm_show_after);
        hook_comm_show = 0;
    }
    if (hook_map_files_get_link) {
        mkpm_unwrap_for_exit(hook_map_files_get_link, map_files_get_link_before, 0);
        hook_map_files_get_link = 0;
    }
    if (hook_proc_map_files_lookup) {
        mkpm_unwrap_for_exit(hook_proc_map_files_lookup, proc_map_files_lookup_before, 0);
        hook_proc_map_files_lookup = 0;
    }
    if (hook_proc_task_instantiate) {
        mkpm_unwrap_for_exit(hook_proc_task_instantiate, proc_thread_instantiate_before, 0);
        hook_proc_task_instantiate = 0;
    }
    if (hook_proc_pid_instantiate) {
        mkpm_unwrap_for_exit(hook_proc_pid_instantiate, proc_thread_instantiate_before, 0);
        hook_proc_pid_instantiate = 0;
    }
    if (hook_proc_fill_cache) {
        mkpm_unwrap_for_exit(hook_proc_fill_cache, proc_fill_cache_before, 0);
        hook_proc_fill_cache = 0;
    }
    if (hook_show_numa_map) {
        mkpm_unwrap_for_exit(hook_show_numa_map, seq_show_before, seq_show_after);
        hook_show_numa_map = 0;
    }
    if (hook_show_smap) {
        mkpm_unwrap_for_exit(hook_show_smap, seq_show_before, seq_smap_after);
        hook_show_smap = 0;
    }
    if (hook_show_map) {
        mkpm_unwrap_for_exit(hook_show_map, seq_show_before, seq_show_after);
        hook_show_map = 0;
    }
}

static int hook_one_symbol(const char *name, void **slot, int argno, void *before, void *after)
{
    void *func;
    hook_err_t err;

    func = (void *)kallsyms_lookup_name(name);
    *slot = func;
    if (!func) {
        pr_info("hide-so: %s not found, skipping\n", name);
        return 0;
    }
    err = hook_wrap(func, argno, before, after, 0);
    if (!err) {
        pr_info("hide-so: hooked %s at %p\n", name, *slot);
        return 0;
    }
    pr_info("hide-so: hook %s failed: %d\n", name, err);
    *slot = 0;
    return -1;
}

/* ---------------------------------------------------------- module ops --- */

/* ctl0 management helpers (defined below, used by init defaults) */
static void hm_reset_tokens(void);
static int hm_add_token(const char *token);
static int hm_set_prefix(const char *prefix);

#ifdef MKPM_MERGED
long hide_so_init(const char *args, const char *event, void *__user reserved)
#else
static long hide_so_init(const char *args, const char *event, void *__user reserved)
#endif
{
    int i;

    (void)reserved;
    hidden_range_count = 0;
    hidden_range_pos = 0;
    memset(getattr_states, 0, sizeof(getattr_states));
    map_state_pos = 0;
    memset(map_states, 0, sizeof(map_states));
    getattr_state_pos = 0;
    /* feature switches: hide-so defaults ON */
    hm_enabled = 1;
    hm_hide_maps = 1;
    hm_hide_threads = 1;
    hm_maps_callback_seen = 0;
    hm_reset_tokens();
    /* Thread comm prefix aligned with current rustFrida marker (ReferenceQueueD). */
    hm_set_prefix("ReferenceQueueD");
    kpm_demo_log_init("hide-so", event, args);

    sym_proc_map_files_instantiate = (void *)kallsyms_lookup_name("proc_map_files_instantiate");
    sym_proc_task_instantiate = (void *)kallsyms_lookup_name("proc_task_instantiate");
    kfn_task_pid_nr_ns = (void *)kallsyms_lookup_name("__task_pid_nr_ns");
    kfn_find_ge_pid = (void *)kallsyms_lookup_name("find_ge_pid");
    kfn_pid_task = (void *)kallsyms_lookup_name("pid_task");
    kfn_pid_nr_ns = (void *)kallsyms_lookup_name("pid_nr_ns");
    kfn_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    kfn_task_active_pid_ns = (void *)kallsyms_lookup_name("task_active_pid_ns");
    kfn_dentry_path = (void *)kallsyms_lookup_name("dentry_path");
    if (sym_proc_task_instantiate)
        pr_info("hide-so: proc_task_instantiate at %p\n", sym_proc_task_instantiate);
    else
        pr_info("hide-so: proc_task_instantiate not found, thread listing hide disabled\n");

    if (hook_one_symbol("show_map", &hook_show_map, 2, seq_show_before, seq_show_after)) {
        unhook_all();
        return -1;
    }
    hook_one_symbol("show_smap", &hook_show_smap, 2, seq_show_before, seq_smap_after);
    hook_one_symbol("show_numa_map", &hook_show_numa_map, 2, seq_show_before, seq_show_after);
    hook_one_symbol("proc_fill_cache", &hook_proc_fill_cache, 7, proc_fill_cache_before, 0);
    hook_one_symbol("proc_pid_instantiate", &hook_proc_pid_instantiate, 3, proc_thread_instantiate_before, 0);
    hook_one_symbol("proc_task_instantiate", &hook_proc_task_instantiate, 3, proc_thread_instantiate_before, 0);
    hook_one_symbol("proc_map_files_lookup", &hook_proc_map_files_lookup, 3, proc_map_files_lookup_before, 0);
    hook_one_symbol("map_files_get_link", &hook_map_files_get_link, 2, map_files_get_link_before, 0);
    hook_one_symbol("cgroup_procs_show", &hook_cgroup_procs_show, 2, seq_show_before, cgroup_procs_show_after);
    hook_one_symbol("cgroup_pidlist_show", &hook_cgroup_pidlist_show, 2, seq_show_before, cgroup_pidlist_show_after);
    hook_one_symbol("comm_show", &hook_comm_show, 2, seq_show_before, comm_show_after);
    hook_one_symbol("proc_pid_status", &hook_proc_pid_status, 4, seq_show_before, proc_pid_status_after);
    hook_one_symbol("do_task_stat", &hook_do_task_stat, 5, seq_show_before, do_task_stat_after);
    hook_one_symbol("proc_sched_show_task", &hook_proc_sched_show_task, 3, seq_arg2_before, proc_sched_show_task_after);
    hook_one_symbol("proc_task_getattr", &hook_proc_task_getattr, 5, proc_task_getattr_before, proc_task_getattr_after);
    hook_one_symbol("proc_tgid_stat", &hook_proc_tgid_stat, 4, seq_show_before, proc_pid_stat_after);
    hook_one_symbol("proc_tid_stat", &hook_proc_tid_stat, 4, seq_show_before, proc_pid_stat_after);
    for (i = 0; i < 20; i++)
        hook_one_symbol(proc_hidden_single_show_symbols[i], &hook_proc_hidden_single_show[i], 4,
                        seq_show_before, proc_hidden_single_show_after);

    pr_info("hide-so: installed, filtering token prefix dalvik-jit-code-cache/qbdi_helper, threads ReferenceQueueD*\n");
    return 0;
}

/* ------------------------------------------------------ ctl0 management --- */

static void hm_reset_tokens(void)
{
    hidden_token_count = 0;
    hidden_tokens[0] = 0;
    /* Defaults aligned with current rustFrida VMA / memfd naming (disguised as
     * Android system resources). Add extra tokens via 'hide token add <s>'. */
    hm_add_token("dalvik-jit-code-cache");
    hm_add_token("qbdi_helper");
}

static int hm_add_token(const char *token)
{
    int i;
    size_t len;

    if (!token)
        return -1;
    len = strlen(token);
    if (!len || len >= HM_TOKEN_LEN)
        return -1;
    for (i = 0; i < hidden_token_count; i++) {
        if (!strcmp(hidden_tokens[i], token))
            return 0;
    }
    if (hidden_token_count >= HM_MAX_TOKENS)
        return -1;
    memcpy(hidden_token_storage[hidden_token_count], token, len + 1);
    hidden_tokens[hidden_token_count] = hidden_token_storage[hidden_token_count];
    hidden_token_count++;
    hidden_tokens[hidden_token_count] = 0;
    return 0;
}

static int hm_del_token(const char *token)
{
    int i, j;

    for (i = 0; i < hidden_token_count; i++) {
        if (strcmp(hidden_tokens[i], token))
            continue;
        for (j = i; j < hidden_token_count - 1; j++) {
            memcpy(hidden_token_storage[j], hidden_token_storage[j + 1], HM_TOKEN_LEN);
            hidden_tokens[j] = hidden_token_storage[j];
        }
        hidden_token_count--;
        hidden_tokens[hidden_token_count] = 0;
        return 0;
    }
    return -1;
}

static int hm_set_prefix(const char *prefix)
{
    size_t len;

    if (!prefix)
        return -1;
    len = strlen(prefix);
    if (!len || len > 15)
        return -1;
    memcpy(thread_hide_prefix, prefix, len + 1);
    thread_hide_prefix_len = (int)len;
    return 0;
}

static int hm_del_range(unsigned long start, unsigned long end)
{
    int i;

    for (i = 0; i < hidden_range_count; i++) {
        if (hidden_ranges[i].start == start && hidden_ranges[i].end == end) {
            hidden_ranges[i] = hidden_ranges[hidden_range_count - 1];
            hidden_ranges[hidden_range_count - 1].start = 0;
            hidden_ranges[hidden_range_count - 1].end = 0;
            hidden_range_count--;
            return 0;
        }
    }
    return -1;
}

/* tiny whitespace tokenizer; modifies nothing, returns args in argv[] */
static int hm_split_args(const char *args, const char **argv, int max_argc)
{
    int argc = 0;
    const char *p = args;

    if (!p)
        return 0;
    while (*p && argc < max_argc) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (!*p)
            break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            p++;
    }
    return argc;
}

/* compare NUL-terminated s against a non-NUL token of length len */
static int hm_token_eq(const char *tok, size_t len, const char *s)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (!s[i] || s[i] != tok[i])
            return 0;
    }
    return s[len] == 0;
}

static size_t hm_token_copy(char *dst, size_t cap, const char *tok, size_t len)
{
    if (len >= cap)
        len = cap - 1;
    memcpy(dst, tok, len);
    dst[len] = 0;
    return len;
}

static size_t hm_tok_len(const char *tok)
{
    size_t len = 0;

    while (tok[len] && tok[len] != ' ' && tok[len] != '\t' && tok[len] != '\r' && tok[len] != '\n')
        len++;
    return len;
}

#ifdef MKPM_MERGED
long hide_so_control0(const char *args, char *__user out_msg, int outlen)
#else
static long hide_so_control0(const char *args, char *__user out_msg, int outlen)
#endif
{
    char msg[1024];
    const char *argv[8];
    int argc;
    int a0 = 0;
    int off = 0;
    int i;

    argc = hm_split_args(args, argv, 8);
    /* allow an optional leading "hide" (merged-mkpm dispatch style) */
    if (argc > 0 && hm_token_eq(argv[0], hm_tok_len(argv[0]), "hide")) {
        a0 = 1;
        argc--;
    }

    /* manual dispatch; tokens are not NUL-terminated, compare with lengths */
#define HM_ARG_IS(n, s) (argc > (n) && hm_token_eq(argv[(n) + a0], hm_tok_len(argv[(n) + a0]), s))
#define HM_ARG_COPY(n, dst, cap) hm_token_copy(dst, cap, argv[(n) + a0], hm_tok_len(argv[(n) + a0]))

    if (argc == 0 || HM_ARG_IS(0, "status")) {
        off += snprintf(msg + off, sizeof(msg) - off,
                        "hide-so: enabled=%d maps=%d threads=%d tokens=%d ranges=%d prefix=",
                        hm_enabled, hm_hide_maps, hm_hide_threads, hidden_token_count,
                        hidden_range_count);
        off += snprintf(msg + off, sizeof(msg) - off, "%s\n", thread_hide_prefix);
        for (i = 0; i < hidden_token_count && off < (int)sizeof(msg) - 40; i++)
            off += snprintf(msg + off, sizeof(msg) - off, "token[%d]=%s\n", i, hidden_tokens[i]);
    } else if (HM_ARG_IS(0, "enable") || HM_ARG_IS(0, "disable")) {
        int on = HM_ARG_IS(0, "enable");
        if (argc < 2) {
            hm_enabled = on;
            off += snprintf(msg + off, sizeof(msg) - off, "ok enabled=%d\n", hm_enabled);
        } else if (HM_ARG_IS(1, "maps")) {
            hm_hide_maps = on;
            off += snprintf(msg + off, sizeof(msg) - off, "ok maps=%d\n", hm_hide_maps);
        } else if (HM_ARG_IS(1, "threads")) {
            hm_hide_threads = on;
            off += snprintf(msg + off, sizeof(msg) - off, "ok threads=%d\n", hm_hide_threads);
        } else {
            off += snprintf(msg + off, sizeof(msg) - off, "error=bad-target\n");
        }
    } else if (HM_ARG_IS(0, "token") && argc >= 2) {
        if (HM_ARG_IS(1, "list")) {
            for (i = 0; i < hidden_token_count && off < (int)sizeof(msg) - 40; i++)
                off += snprintf(msg + off, sizeof(msg) - off, "token[%d]=%s\n", i, hidden_tokens[i]);
            if (!hidden_token_count)
                off += snprintf(msg + off, sizeof(msg) - off, "(no tokens)\n");
        } else if (argc >= 3 && (HM_ARG_IS(1, "add") || HM_ARG_IS(1, "del"))) {
            char tok[HM_TOKEN_LEN];
            HM_ARG_COPY(2, tok, sizeof(tok));
            if (HM_ARG_IS(1, "add"))
                off += snprintf(msg + off, sizeof(msg) - off, "%s\n", hm_add_token(tok) ? "error=add" : "ok");
            else
                off += snprintf(msg + off, sizeof(msg) - off, "%s\n", hm_del_token(tok) ? "error=del" : "ok");
        } else {
            off += snprintf(msg + off, sizeof(msg) - off, "error=usage token list|add <t>|del <t>\n");
        }
    } else if (HM_ARG_IS(0, "prefix") && argc >= 2) {
        if (HM_ARG_IS(1, "show")) {
            off += snprintf(msg + off, sizeof(msg) - off, "prefix=%s\n", thread_hide_prefix);
        } else if (HM_ARG_IS(1, "set") && argc >= 3) {
            char pfx[16];
            HM_ARG_COPY(2, pfx, sizeof(pfx));
            off += snprintf(msg + off, sizeof(msg) - off, "%s\n", hm_set_prefix(pfx) ? "error=set" : "ok");
        } else {
            off += snprintf(msg + off, sizeof(msg) - off, "error=usage prefix show|set <p>\n");
        }
    } else if (HM_ARG_IS(0, "range") && argc >= 2) {
        if (HM_ARG_IS(1, "list")) {
            int shown = 0;
            for (i = 0; i < hidden_range_count && shown < 16 && off < (int)sizeof(msg) - 48; i++) {
                if (!hidden_ranges[i].start)
                    continue;
                off += snprintf(msg + off, sizeof(msg) - off, "%lx-%lx\n",
                                hidden_ranges[i].start, hidden_ranges[i].end);
                shown++;
            }
            off += snprintf(msg + off, sizeof(msg) - off, "count=%d\n", hidden_range_count);
        } else if (HM_ARG_IS(1, "clear")) {
            hidden_range_count = 0;
            hidden_range_pos = 0;
            memset(hidden_ranges, 0, sizeof(hidden_ranges));
            off += snprintf(msg + off, sizeof(msg) - off, "ok cleared\n");
        } else if (argc >= 3 && (HM_ARG_IS(1, "add") || HM_ARG_IS(1, "del"))) {
            char spec[48];
            unsigned long start = 0, end = 0;
            HM_ARG_COPY(2, spec, sizeof(spec));
            if (!parse_range_name(spec, strlen(spec), &start, &end)) {
                off += snprintf(msg + off, sizeof(msg) - off, "error=bad-range\n");
            } else if (HM_ARG_IS(1, "add")) {
                remember_hidden_range(start, end);
                off += snprintf(msg + off, sizeof(msg) - off, "ok ranges=%d\n", hidden_range_count);
            } else {
                off += snprintf(msg + off, sizeof(msg) - off, "%s\n",
                                hm_del_range(start, end) ? "error=not-found" : "ok");
            }
        } else {
            off += snprintf(msg + off, sizeof(msg) - off, "error=usage range list|add <s>-<e>|del <s>-<e>|clear\n");
        }
    } else {
        off += snprintf(msg + off, sizeof(msg) - off,
                        "usage: status|enable [maps|threads]|disable [maps|threads]|"
                        "token list|add <t>|del <t>|prefix show|set <p>|range list|add <s>-<e>|del <s>-<e>|clear\n");
    }

    pr_info("hide-so: ctl %s -> %s", args ? args : "(null)", msg);
    if (!out_msg || outlen <= 0)
        return 0;
    if (off >= outlen)
        off = outlen - 1;
    return compat_copy_to_user(out_msg, msg, off + 1);
}

#ifdef MKPM_MERGED
long hide_so_exit(void *__user reserved)
#else
static long hide_so_exit(void *__user reserved)
#endif
{
    (void)reserved;
    unhook_all();
    return kpm_demo_log_exit("hide-so");
}

#ifndef MKPM_MERGED
KPM_INIT(hide_so_init);
KPM_CTL0(hide_so_control0);
KPM_EXIT(hide_so_exit);
#endif
