/*
 * Lightweight syscall recorder for dysvcpit.
 *
 * The hot path writes a bounded record into a fixed ring.  Records are fetched
 * through KPM_CTL0 by default.  A controller may explicitly enable one-line
 * pr_info() output for dmesg-oriented sessions after narrowing the filter.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <syscall.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>

#include "opts.h"
#include "sysmon.h"

#define SYSMON_RING_CAP       128
#define SYSMON_MAX_HOOKS      16
#define SYSMON_MAX_READ       8
#define SYSMON_PATH_MAX       96
#define SYSMON_COMM_LEN       16
#define SYSMON_ACTIVE_MARKER  0x53594d4f4eULL /* "SYMON" */

struct sysmon_event {
    u64 seq;
    u64 args[6];
    s64 ret;
    u32 nr;
    u32 tid;
    u32 tgid;
    u32 uid;
    char comm[SYSMON_COMM_LEN];
    char path[SYSMON_PATH_MAX];
};

struct sysmon_hook {
    int nr;
    int narg;
    bool attached;
};

struct sysmon_reply {
    char *buf;
    int cap;
    int len;
};

static struct sysmon_event g_ring[SYSMON_RING_CAP];
static struct sysmon_hook g_hooks[SYSMON_MAX_HOOKS];
static u64 g_next_seq;
static u64 g_dropped;

static volatile int g_enabled;
static volatile int g_target_uid;
static volatile int g_target_tgid;
static volatile int g_capture_path;
static volatile int g_emit_dmesg;

static void reply_ch(struct sysmon_reply *r, char c)
{
    if (!r || r->cap <= 1)
        return;
    if (r->len < r->cap - 1)
        r->buf[r->len++] = c;
}

static void reply_str(struct sysmon_reply *r, const char *s)
{
    if (!s)
        return;
    while (*s)
        reply_ch(r, *s++);
}

static void reply_u64(struct sysmon_reply *r, u64 value, unsigned int base)
{
    static const char digits[] = "0123456789abcdef";
    char tmp[24];
    int n = 0;

    if (base < 2 || base > 16)
        return;
    if (value == 0) {
        reply_ch(r, '0');
        return;
    }
    while (value && n < (int)sizeof(tmp)) {
        tmp[n++] = digits[value % base];
        value /= base;
    }
    while (n)
        reply_ch(r, tmp[--n]);
}

static void reply_i64(struct sysmon_reply *r, s64 value)
{
    if (value < 0) {
        reply_ch(r, '-');
        reply_u64(r, (u64)(-(value + 1)) + 1, 10);
        return;
    }
    reply_u64(r, (u64)value, 10);
}

static void reply_hex(struct sysmon_reply *r, u64 value)
{
    reply_str(r, "0x");
    reply_u64(r, value, 16);
}

static void reply_finish(struct sysmon_reply *r)
{
    if (!r || r->cap <= 0)
        return;
    if (r->len >= r->cap)
        r->len = r->cap - 1;
    r->buf[r->len] = '\0';
}

static int reply_copy(struct sysmon_reply *r, char __user *out_msg, int outlen)
{
    reply_finish(r);
    if (!out_msg || outlen <= 0)
        return 0;
    return compat_copy_to_user(out_msg, r->buf, r->len + 1);
}

static bool parse_u64(const char *text, unsigned int default_base, u64 *out)
{
    unsigned int base = default_base;
    u64 value = 0;
    const char *p = text;

    if (!p || !*p || !out || base < 2 || base > 16)
        return false;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
        if (!*p)
            return false;
    }
    while (*p) {
        unsigned int digit;
        char c = *p++;

        if (c >= '0' && c <= '9')
            digit = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f')
            digit = (unsigned int)(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F')
            digit = (unsigned int)(c - 'A') + 10;
        else
            return false;
        if (digit >= base || value > (~0ULL - digit) / base)
            return false;
        value = value * base + digit;
    }
    *out = value;
    return true;
}

static bool parse_nonnegative_int(const char *text, int *out)
{
    u64 value;

    if (!parse_u64(text, 10, &value) || value > 0x7fffffffULL)
        return false;
    *out = (int)value;
    return true;
}

/* Read pid/tgid directly via task_struct_offset to avoid __task_pid_nr_ns */
static inline pid_t sysmon_task_pid(struct task_struct *task)
{
    return *(pid_t *)(((uintptr_t)task) + task_struct_offset.pid_offset);
}

static inline pid_t sysmon_task_tgid(struct task_struct *task)
{
    return *(pid_t *)(((uintptr_t)task) + task_struct_offset.tgid_offset);
}

static bool sysmon_matches_filter(void)
{
    struct task_struct *task = current;
    int uid_filter = g_target_uid;
    int tgid_filter = g_target_tgid;
    int uid = (int)current_uid();
    int tgid = (int)sysmon_task_pid(task);

    if (!g_enabled)
        return false;
    if (uid_filter >= 0 && uid != uid_filter)
        return false;
    if (tgid_filter >= 0 && tgid != tgid_filter)
        return false;
    return true;
}

static void sysmon_copy_comm(char dst[SYSMON_COMM_LEN], const char *src)
{
    int i;

    if (!src) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i < SYSMON_COMM_LEN - 1 && src[i]; ++i) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    dst[i] = '\0';
}

static void sysmon_capture_path(struct sysmon_event *event)
{
    const char __user *user_path;
    long copied;

    event->path[0] = '\0';
    if (!g_capture_path)
        return;
    if (event->nr != __NR_openat && event->nr != __NR_openat2)
        return;

    user_path = (const char __user *)(uintptr_t)event->args[1];
    if (!user_path)
        return;
    copied = compat_strncpy_from_user(event->path, user_path, sizeof(event->path));
    if (copied < 0) {
        event->path[0] = '!';
        event->path[1] = '\0';
        return;
    }
    event->path[SYSMON_PATH_MAX - 1] = '\0';
    for (int i = 0; event->path[i]; ++i) {
        unsigned char c = (unsigned char)event->path[i];
        if (c < 0x20 || c == 0x7f || c == ' ')
            event->path[i] = '?';
    }
}

static void sysmon_emit_dmesg(const struct sysmon_event *event)
{
    if (!g_emit_dmesg)
        return;

    pr_info("dysvcpit-syscall seq=%llu nr=%u tid=%u tgid=%u uid=%u ret=%lld comm=%s a0=%llx a1=%llx a2=%llx a3=%llx a4=%llx a5=%llx path=%s\n",
            (unsigned long long)event->seq, event->nr, event->tid,
            event->tgid, event->uid, (long long)event->ret, event->comm,
            (unsigned long long)event->args[0],
            (unsigned long long)event->args[1],
            (unsigned long long)event->args[2],
            (unsigned long long)event->args[3],
            (unsigned long long)event->args[4],
            (unsigned long long)event->args[5],
            event->path[0] ? event->path : "-");
}

static void sysmon_record(int nr, const u64 args[6], s64 ret)
{
    struct sysmon_event event;
    struct task_struct *task = current;
    u64 seq;
    int i;

    event.seq = 0;
    for (i = 0; i < 6; ++i)
        event.args[i] = args[i];
    event.ret = ret;
    event.nr = (u32)nr;
    event.tid = (u32)sysmon_task_pid(task);
    event.tgid = (u32)sysmon_task_tgid(task);
    event.uid = (u32)current_uid();
    sysmon_copy_comm(event.comm, get_task_comm(task));
    sysmon_capture_path(&event);

    /* Atomic seq assignment without spinlock (avoids _raw_spin_lock_irqsave) */
    seq = __atomic_fetch_add(&g_next_seq, 1, __ATOMIC_RELAXED);
    event.seq = seq + 1;
    if (event.seq > SYSMON_RING_CAP)
        __atomic_fetch_add(&g_dropped, 1, __ATOMIC_RELAXED);
    g_ring[event.seq % SYSMON_RING_CAP] = event;

    sysmon_emit_dmesg(&event);
}

static void sysmon_before(hook_fargs6_t *args, void *udata)
{
    int i;

    (void)udata;
    if (!sysmon_matches_filter()) {
        args->local.data0 = 0;
        return;
    }
    args->local.data0 = SYSMON_ACTIVE_MARKER;
    for (i = 0; i < 6; ++i)
        args->local.data[i + 1] = syscall_argn(args, i);
}

static void sysmon_after(hook_fargs6_t *args, void *udata)
{
    struct sysmon_hook *hook = (struct sysmon_hook *)udata;
    u64 saved_args[6];
    int i;

    if (args->local.data0 != SYSMON_ACTIVE_MARKER || !hook)
        return;
    for (i = 0; i < 6; ++i)
        saved_args[i] = args->local.data[i + 1];
    sysmon_record(hook->nr, saved_args, (s64)args->ret);
}

static int sysmon_find_hook(int nr)
{
    int i;

    for (i = 0; i < SYSMON_MAX_HOOKS; ++i) {
        if (g_hooks[i].attached && g_hooks[i].nr == nr)
            return i;
    }
    return -1;
}

static int sysmon_find_free_hook(void)
{
    int i;

    for (i = 0; i < SYSMON_MAX_HOOKS; ++i) {
        if (!g_hooks[i].attached)
            return i;
    }
    return -1;
}

static int sysmon_attach(int nr, int narg)
{
    int slot;
    hook_err_t err;

    if (nr < 0 || nr >= 460 || narg < 0 || narg > 6)
        return -EINVAL;
    if (sysmon_find_hook(nr) >= 0)
        return -EEXIST;
    slot = sysmon_find_free_hook();
    if (slot < 0)
        return -ENOSPC;

    g_hooks[slot].nr = nr;
    g_hooks[slot].narg = narg;
    err = hook_syscalln(nr, narg, sysmon_before, sysmon_after, &g_hooks[slot]);
    if (err != HOOK_NO_ERR)
        return -(int)err;
    g_hooks[slot].attached = true;
    return 0;
}

static int sysmon_detach(int nr)
{
    int slot = sysmon_find_hook(nr);

    if (slot < 0)
        return -ENOENT;
    g_enabled = 0;
    unhook_syscalln(g_hooks[slot].nr, sysmon_before, sysmon_after);
    g_hooks[slot].attached = false;
    return 0;
}

static void sysmon_detach_all(void)
{
    int i;

    g_enabled = 0;
    for (i = 0; i < SYSMON_MAX_HOOKS; ++i) {
        if (!g_hooks[i].attached)
            continue;
        unhook_syscalln(g_hooks[i].nr, sysmon_before, sysmon_after);
        g_hooks[i].attached = false;
    }
}

static void sysmon_clear_events(void)
{
    g_next_seq = 1;
    g_dropped = 0;
    for (int i = 0; i < SYSMON_RING_CAP; ++i)
        g_ring[i].seq = 0;
}

static int sysmon_attach_preset_io(void)
{
    static const struct {
        int nr;
        int narg;
    } preset[] = {
        { __NR_openat, 4 },
        { __NR_openat2, 4 },
        { __NR_read, 3 },
        { __NR_write, 3 },
        { __NR_connect, 3 },
        { __NR_sendto, 6 },
        { __NR_recvfrom, 6 },
    };
    int first_error = 0;
    int i;

    for (i = 0; i < (int)(sizeof(preset) / sizeof(preset[0])); ++i) {
        int ret;

        if (sysmon_find_hook(preset[i].nr) >= 0)
            continue;
        ret = sysmon_attach(preset[i].nr, preset[i].narg);
        if (ret && !first_error)
            first_error = ret;
    }
    return first_error;
}

static void sysmon_reply_status(struct sysmon_reply *reply)
{
    u64 next_seq;
    u64 dropped;
    int hooks = 0;
    int i;

    next_seq = g_next_seq;
    dropped = g_dropped;

    for (i = 0; i < SYSMON_MAX_HOOKS; ++i)
        if (g_hooks[i].attached)
            ++hooks;

    reply_str(reply, "enabled=");
    reply_u64(reply, (u64)g_enabled, 10);
    reply_str(reply, " uid=");
    reply_i64(reply, (s64)g_target_uid);
    reply_str(reply, " tgid=");
    reply_i64(reply, (s64)g_target_tgid);
    reply_str(reply, " path=");
    reply_u64(reply, (u64)g_capture_path, 10);
    reply_str(reply, " dmesg=");
    reply_u64(reply, (u64)g_emit_dmesg, 10);
    reply_str(reply, " wrapper=");
    reply_u64(reply, (u64)has_syscall_wrapper, 10);
    reply_str(reply, " hooks=");
    reply_u64(reply, (u64)hooks, 10);
    reply_str(reply, " next=");
    reply_u64(reply, next_seq, 10);
    reply_str(reply, " dropped=");
    reply_u64(reply, dropped, 10);
    reply_ch(reply, '\n');

    for (i = 0; i < SYSMON_MAX_HOOKS; ++i) {
        if (!g_hooks[i].attached)
            continue;
        reply_str(reply, "hook nr=");
        reply_i64(reply, g_hooks[i].nr);
        reply_str(reply, " narg=");
        reply_i64(reply, g_hooks[i].narg);
        reply_ch(reply, '\n');
    }
}

static void sysmon_reply_event(struct sysmon_reply *reply,
                               const struct sysmon_event *event)
{
    int i;

    reply_str(reply, "event seq=");
    reply_u64(reply, event->seq, 10);
    reply_str(reply, " nr=");
    reply_u64(reply, event->nr, 10);
    reply_str(reply, " tid=");
    reply_u64(reply, event->tid, 10);
    reply_str(reply, " tgid=");
    reply_u64(reply, event->tgid, 10);
    reply_str(reply, " uid=");
    reply_u64(reply, event->uid, 10);
    reply_str(reply, " ret=");
    reply_i64(reply, event->ret);
    reply_str(reply, " comm=");
    reply_str(reply, event->comm);
    for (i = 0; i < 6; ++i) {
        reply_str(reply, " a");
        reply_u64(reply, i, 10);
        reply_ch(reply, '=');
        reply_hex(reply, event->args[i]);
    }
    if (event->path[0]) {
        reply_str(reply, " path=");
        reply_str(reply, event->path);
    }
    reply_ch(reply, '\n');
}

static void sysmon_reply_read(struct sysmon_reply *reply, u64 after, int limit)
{
    struct sysmon_event events[SYSMON_MAX_READ];
    u64 next_seq;
    u64 oldest;
    u64 seq;
    u64 lost = 0;
    int count = 0;

    if (limit < 1)
        limit = 1;
    if (limit > SYSMON_MAX_READ)
        limit = SYSMON_MAX_READ;

    next_seq = g_next_seq;
    oldest = next_seq > SYSMON_RING_CAP ? next_seq - SYSMON_RING_CAP : 1;
    seq = after + 1;
    if (seq < oldest) {
        lost = oldest - seq;
        seq = oldest;
    }
    while (seq < next_seq && count < limit) {
        struct sysmon_event *source = &g_ring[seq % SYSMON_RING_CAP];
        if (source->seq == seq)
            events[count++] = *source;
        ++seq;
    }

    reply_str(reply, "next=");
    reply_u64(reply, next_seq, 10);
    reply_str(reply, " oldest=");
    reply_u64(reply, oldest, 10);
    reply_str(reply, " lost=");
    reply_u64(reply, lost, 10);
    reply_str(reply, " count=");
    reply_u64(reply, count, 10);
    reply_ch(reply, '\n');
    for (int i = 0; i < count; ++i)
        sysmon_reply_event(reply, &events[i]);
}

static void sysmon_reply_help(struct sysmon_reply *reply)
{
    reply_str(reply,
        "syscall attach <nr> <narg> | detach <nr> | detach-all\n"
        "syscall preset io | start | stop | clear | status\n"
        "syscall filter uid <uid>|tgid <pid>|clear\n"
        "syscall path on|off | dmesg on|off | read <after-seq> [max]\n");
}

int sysmon_main(struct opts *opts, char __user *out_msg, int outlen)
{
    char reply_buf[2048];
    struct sysmon_reply reply = {
        .buf = reply_buf,
        .cap = sizeof(reply_buf),
        .len = 0,
    };
    int ret = -EINVAL;

    if (!opts || opts->size < 2) {
        sysmon_reply_help(&reply);
        reply_copy(&reply, out_msg, outlen);
        return -EINVAL;
    }

    if (!strcmp(opts->args[1], "help")) {
        sysmon_reply_help(&reply);
        ret = 0;
    } else if (!strcmp(opts->args[1], "start")) {
        g_enabled = 1;
        reply_str(&reply, "ok enabled=1\n");
        ret = 0;
    } else if (!strcmp(opts->args[1], "stop")) {
        g_enabled = 0;
        reply_str(&reply, "ok enabled=0\n");
        ret = 0;
    } else if (!strcmp(opts->args[1], "clear")) {
        sysmon_clear_events();
        reply_str(&reply, "ok cleared\n");
        ret = 0;
    } else if (!strcmp(opts->args[1], "status")) {
        sysmon_reply_status(&reply);
        ret = 0;
    } else if (!strcmp(opts->args[1], "attach") && opts->size >= 4) {
        int nr;
        int narg;

        if (parse_nonnegative_int(opts->args[2], &nr) &&
            parse_nonnegative_int(opts->args[3], &narg))
            ret = sysmon_attach(nr, narg);
        if (!ret)
            reply_str(&reply, "ok attached\n");
    } else if (!strcmp(opts->args[1], "detach") && opts->size >= 3) {
        int nr;

        if (parse_nonnegative_int(opts->args[2], &nr))
            ret = sysmon_detach(nr);
        if (!ret)
            reply_str(&reply, "ok detached; enabled=0\n");
    } else if (!strcmp(opts->args[1], "detach-all")) {
        sysmon_detach_all();
        reply_str(&reply, "ok detached-all\n");
        ret = 0;
    } else if (!strcmp(opts->args[1], "preset") && opts->size >= 3 &&
               !strcmp(opts->args[2], "io")) {
        ret = sysmon_attach_preset_io();
        if (!ret)
            reply_str(&reply, "ok preset=io\n");
    } else if (!strcmp(opts->args[1], "filter") && opts->size >= 3) {
        if (!strcmp(opts->args[2], "clear")) {
            g_target_uid = -1;
            g_target_tgid = -1;
            reply_str(&reply, "ok filter=clear\n");
            ret = 0;
        } else if (opts->size >= 4 && !strcmp(opts->args[2], "uid")) {
            int value;
            if (parse_nonnegative_int(opts->args[3], &value)) {
                g_target_uid = value;
                reply_str(&reply, "ok filter=uid\n");
                ret = 0;
            }
        } else if (opts->size >= 4 && !strcmp(opts->args[2], "tgid")) {
            int value;
            if (parse_nonnegative_int(opts->args[3], &value)) {
                g_target_tgid = value;
                reply_str(&reply, "ok filter=tgid\n");
                ret = 0;
            }
        }
    } else if (!strcmp(opts->args[1], "path") && opts->size >= 3) {
        if (!strcmp(opts->args[2], "on")) {
            g_capture_path = 1;
            reply_str(&reply, "ok path=1\n");
            ret = 0;
        } else if (!strcmp(opts->args[2], "off")) {
            g_capture_path = 0;
            reply_str(&reply, "ok path=0\n");
            ret = 0;
        }
    } else if (!strcmp(opts->args[1], "dmesg") && opts->size >= 3) {
        if (!strcmp(opts->args[2], "on")) {
            g_emit_dmesg = 1;
            reply_str(&reply, "ok dmesg=1\n");
            ret = 0;
        } else if (!strcmp(opts->args[2], "off")) {
            g_emit_dmesg = 0;
            reply_str(&reply, "ok dmesg=0\n");
            ret = 0;
        }
    } else if (!strcmp(opts->args[1], "read")) {
        u64 after = 0;
        int limit = 16;

        if (opts->size >= 3 && !parse_u64(opts->args[2], 10, &after))
            ret = -EINVAL;
        else if (opts->size >= 4 && !parse_nonnegative_int(opts->args[3], &limit))
            ret = -EINVAL;
        else {
            sysmon_reply_read(&reply, after, limit);
            ret = 0;
        }
    }

    if (ret) {
        reply.len = 0;
        reply_str(&reply, "error=");
        reply_i64(&reply, ret);
        reply_ch(&reply, '\n');
    }
    reply_copy(&reply, out_msg, outlen);
    return ret;
}

int sysmon_init(void)
{
    g_enabled = 0;
    g_target_uid = -1;
    g_target_tgid = -1;
    g_capture_path = 0;
    g_emit_dmesg = 0;
    sysmon_clear_events();
    return 0;
}

void sysmon_exit(void)
{
    g_emit_dmesg = 0;
    sysmon_detach_all();
    sysmon_clear_events();
}
