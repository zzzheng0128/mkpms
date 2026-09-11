/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * boottime.c - 只对指定 UID 改写 CLOCK_BOOTTIME 返回值的可控演示模块。
 *
 * 这里挂的是 clock_gettime(2) 的 after hook，不改全局 timekeeper，也不影响
 * root shell 或其他进程。目标进程成功返回 timespec 后，按配置减去偏移；因此
 * App 和 root shell 读取同一设备时可以直接看到约 600 秒的差异。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <asm/current.h>
#include "../compat/hook_lifecycle.h"

#include "boottime.h"
#include "../../common/kpm_demo_helpers.h"

#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

#define NSEC_PER_SEC 1000000000LL
#define BOOTTIME_DEFAULT_UID 0

/* arm64 用户态 timespec 与内核 timespec64 都是两个 64 位成员。 */
struct bt_timespec64 {
    s64 tv_sec;
    s64 tv_nsec;
};

static volatile int bt_ready;
static volatile int bt_hooked;
static volatile uid_t bt_target_uid = BOOTTIME_DEFAULT_UID;
static volatile s64 bt_offset_ns;
static volatile u64 bt_hits;
static unsigned long (*bt_copy_from_user)(void *to, const void __user *from,
                                           unsigned long n);

static int bt_parse_s64(const char *s, s64 *out)
{
    int neg = 0;
    s64 value = 0;

    if (!s || !*s || !out)
        return -1;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    if (!*s)
        return -1;
    while (*s >= '0' && *s <= '9') {
        if (value > (900000000000000000LL / 10))
            return -1;
        value = value * 10 + (*s - '0');
        s++;
    }
    if (*s)
        return -1;
    *out = neg ? -value : value;
    return 0;
}

static int bt_uid_matches(void)
{
    return bt_target_uid > 0 && current_uid() == bt_target_uid;
}

static void bt_apply_offset(struct bt_timespec64 *tp)
{
    s64 total;
    s64 sec;
    s64 nsec;

    if (!tp || !bt_offset_ns)
        return;
    total = tp->tv_sec * NSEC_PER_SEC + tp->tv_nsec - bt_offset_ns;
    sec = total / NSEC_PER_SEC;
    nsec = total % NSEC_PER_SEC;
    if (nsec < 0) {
        nsec += NSEC_PER_SEC;
        sec--;
    }
    tp->tv_sec = sec;
    tp->tv_nsec = nsec;
}

/* syscall after 回调：args[0] 是 clock id，args[1] 是用户态 timespec 指针。 */
static void bt_clock_after(hook_fargs2_t *args, void *udata)
{
    struct bt_timespec64 tp;
    void __user *user_tp;
    u64 hit;

    (void)udata;
    if (!bt_ready || !bt_hooked || !args || args->ret < 0 ||
        !bt_uid_matches() || (int)syscall_argn(args, 0) != CLOCK_BOOTTIME)
        return;
    user_tp = (void __user *)(uintptr_t)syscall_argn(args, 1);
    if (!user_tp || !bt_copy_from_user || bt_copy_from_user(&tp, user_tp, sizeof(tp)))
        return;
    bt_apply_offset(&tp);
    if (compat_copy_to_user(user_tp, &tp, sizeof(tp)) != sizeof(tp))
        return;
    hit = __atomic_fetch_add(&bt_hits, 1, __ATOMIC_RELAXED) + 1;
    if (hit == 1)
        pr_info("mkpm-boottime: first rewrite uid=%u offset_ns=%lld\n",
                bt_target_uid, (long long)bt_offset_ns);
}

int boottime_init(void)
{
    hook_err_t err;

    bt_ready = 0;
    bt_hooked = 0;
    bt_hits = 0;
    bt_offset_ns = 0;
    bt_copy_from_user = (typeof(bt_copy_from_user))
        kallsyms_lookup_name("_copy_from_user");
    if (!bt_copy_from_user)
        bt_copy_from_user = (typeof(bt_copy_from_user))
            kallsyms_lookup_name("copy_from_user");
    /* Pixel/GKI 通常隐藏 copy_from_user，但会导出 nofault 版本；clock_gettime
     * 已经校验过用户指针，after hook 只需读取这个刚写出的 timespec。 */
    if (!bt_copy_from_user)
        bt_copy_from_user = (typeof(bt_copy_from_user))
            kallsyms_lookup_name("copy_from_user_nofault");
    if (!bt_copy_from_user)
        bt_copy_from_user = (typeof(bt_copy_from_user))
            kallsyms_lookup_name("__arch_copy_from_user");
    if (!bt_copy_from_user) {
        pr_err("mkpm-boottime: copy_from_user unavailable\n");
        return -1;
    }
    err = hook_syscalln(__NR_clock_gettime, 2, 0, bt_clock_after, 0);
    if (err) {
        pr_err("mkpm-boottime: clock_gettime hook failed: %d\n", err);
        bt_copy_from_user = 0;
        return err;
    }
    bt_hooked = 1;
    bt_ready = 1;
    pr_info("mkpm-boottime: ready syscall=%d\n", __NR_clock_gettime);
    return 0;
}

void boottime_exit(void)
{
    if (bt_hooked)
        unhook_syscalln(__NR_clock_gettime, 0, bt_clock_after);
    bt_hooked = 0;
    bt_ready = 0;
    bt_copy_from_user = 0;
}

/* 总 KPM 即将释放代码时使用安全卸载变体；普通 `boot off` 仍保留
 * 原有真正 detach 语义，便于随后重新启用并继续演示。 */
void boottime_unload(void)
{
    if (bt_hooked)
        mkpm_unhook_syscall_for_exit(__NR_clock_gettime, 0, bt_clock_after);
    bt_hooked = 0;
    bt_ready = 0;
    bt_copy_from_user = 0;
}

int boottime_status(char *out, int outlen)
{
    if (!out || outlen <= 0)
        return -1;
    return snprintf(out, outlen,
                    "boottime: ready=%d hooked=%d uid=%u offset_ns=%lld hits=%llu\n",
                    bt_ready, bt_hooked, bt_target_uid,
                    (long long)bt_offset_ns, (unsigned long long)bt_hits);
}

/* boot off 后允许下一轮实验重新启用同一条 syscall hook。主入口的
 * mkpm_boottime_on 记录的是“子系统曾初始化”，而不是当前 hook 是否仍在链
 * 上，所以 uid/time 命令要在这里补一次惰性初始化。 */
static int bt_ensure_hooked(void)
{
    if (bt_hooked && bt_ready)
        return 0;
    return boottime_init();
}

int boottime_main(struct opts *opts, char *out, int outlen)
{
    const char *cmd;
    s64 sec, msec, offset;

    if (!opts || opts->size < 2)
        return boottime_status(out, outlen);
    cmd = opts->args[1];
    if (!strcmp(cmd, "status"))
        return boottime_status(out, outlen);
    if (!strcmp(cmd, "clear")) {
        bt_offset_ns = 0;
        return boottime_status(out, outlen);
    }
    if (!strcmp(cmd, "off")) {
        boottime_exit();
        return snprintf(out, outlen, "boottime: ready=0 hooked=0 uid=%u offset_ns=0 hits=%llu\n",
                        bt_target_uid, (unsigned long long)bt_hits);
    }
    if (!strcmp(cmd, "uid") && opts->size >= 3 &&
        !bt_parse_s64(opts->args[2], &sec) && sec > 0 && sec < 1000000) {
        if (bt_ensure_hooked())
            return snprintf(out, outlen, "error=boottime-init\n");
        bt_target_uid = (uid_t)sec;
        return boottime_status(out, outlen);
    }
    if (!strcmp(cmd, "time") && opts->size >= 3 &&
        !bt_parse_s64(opts->args[2], &sec)) {
        msec = 0;
        if (opts->size >= 4 && bt_parse_s64(opts->args[3], &msec))
            return snprintf(out, outlen, "error=bad-msec\n");
        if (msec <= -1000 || msec >= 1000)
            return snprintf(out, outlen, "error=msec-range\n");
        if (bt_ensure_hooked())
            return snprintf(out, outlen, "error=boottime-init\n");
        offset = sec * NSEC_PER_SEC + msec * 1000000LL;
        bt_offset_ns = offset;
        return boottime_status(out, outlen);
    }
    return snprintf(out, outlen, "usage: boot status|uid <uid>|time <sec> [msec]|clear|off\n");
}
