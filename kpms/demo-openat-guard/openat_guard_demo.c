/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * openat 返回替换 demo（默认关闭）。
 *
 * 默认只安装 hook；只有通过 ctl0 明确给出 UID 和测试路径后，才会
 * 对该 UID 的匹配 openat 返回 -EPERM。它不隐藏进程、不改 maps、不重定向
 * 系统路径，方便在自有测试应用中验证 before 回调和 skip_origin 链路。
 */
#include <compiler.h>
#include <barrier.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("kpm-openat-guard-demo", "1.0.0", "GPL v2", "rustfrida",
                "Scoped openat return replacement demo");

#define PATH_CAP 128
#define TEST_ROOT "/data/local/tmp/"

static volatile int g_enabled;
static volatile int g_uid;
static char g_prefix[PATH_CAP];
static int g_hooked;

static long reply(const char *message, char *__user out_msg, int outlen)
{
    int len;
    int copied;

    if (!out_msg || outlen <= 0)
        return 0;
    len = strlen(message);
    if (len >= outlen)
        len = outlen - 1;
    copied = compat_copy_to_user(out_msg, message, len + 1);
    if (copied != len + 1)
        return -EFAULT;
    return len;
}

static const char *guard_skip_spaces(const char *p)
{
    while (p && (*p == ' ' || *p == '\t'))
        p++;
    return p;
}

static int parse_uid(const char **cursor, int *uid)
{
    const char *p = guard_skip_spaces(*cursor);
    int value = 0;
    int digits = 0;

    while (p && *p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        if (value > 1000000)
            return -EINVAL;
        p++;
        digits++;
    }
    if (!digits || value <= 0)
        return -EINVAL;
    *uid = value;
    *cursor = p;
    return 0;
}

static int copy_prefix(const char *source)
{
    size_t i = 0;

    source = guard_skip_spaces(source);
    while (source && source[i] && source[i] != ' ' && source[i] != '\t' && i < PATH_CAP - 1) {
        g_prefix[i] = source[i];
        i++;
    }
    g_prefix[i] = 0;
    if (source && source[i] && source[i] != ' ' && source[i] != '\t')
        return -EINVAL;
    if (strncmp(g_prefix, TEST_ROOT, strlen(TEST_ROOT)) != 0)
        return -EINVAL;
    return 0;
}

static int is_match(const char *path)
{
    size_t length;

    if (!g_enabled || !g_uid || current_uid() != (uid_t)g_uid || !g_prefix[0] || !path)
        return 0;
    length = strlen(g_prefix);
    return !strncmp(path, g_prefix, length);
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *user_path;
    char path[PATH_CAP];
    long length;

    (void)udata;
    if (!g_enabled || !g_uid || current_uid() != (uid_t)g_uid)
        return;
    user_path = (const char __user *)syscall_argn(args, 1);
    length = compat_strncpy_from_user(path, user_path, sizeof(path));
    if (length <= 0)
        return;
    path[PATH_CAP - 1] = 0;
    if (!is_match(path))
        return;

    pr_info("openat-guard-demo: replacing uid=%d path=%s with -EPERM\n", g_uid, path);
    args->ret = -EPERM;
    args->skip_origin = 1;
}

static int install_hook(void)
{
    hook_err_t error;

    if (g_hooked)
        return 0;
    error = hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    if (error)
        return error;
    g_hooked = 1;
    pr_info("openat-guard-demo: openat hook installed (replacement disabled)\n");
    return 0;
}

static long openat_guard_init(const char *args, const char *event, void *__user reserved)
{
    int error;

    (void)reserved;
    g_enabled = 0;
    g_uid = 0;
    g_prefix[0] = 0;
    error = install_hook();
    if (error)
        return error;
    return kpm_demo_log_init("kpm openat-guard-demo", event, args);
}

static long openat_guard_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *cursor = args;
    int uid;

    if (!args || !*args || !strcmp(args, "status")) {
        char message[220];
        snprintf(message, sizeof(message), "enabled=%d uid=%d prefix=%s\n",
                 g_enabled, g_uid, g_prefix[0] ? g_prefix : "(none)");
        return reply(message, out_msg, outlen);
    }
    if (!strcmp(args, "allow") || !strcmp(args, "observe")) {
        g_enabled = 0;
        return reply("ok mode=observe\n", out_msg, outlen);
    }
    if (strncmp(args, "deny ", 5) != 0)
        return reply("usage: status|observe|deny <uid> <absolute-test-prefix>\n", out_msg, outlen);

    cursor += 5;
    if (parse_uid(&cursor, &uid))
        return reply("error: uid must be a positive decimal\n", out_msg, outlen);
    cursor = guard_skip_spaces(cursor);
    if (!cursor || cursor[0] != '/')
        return reply("error: path must be absolute\n", out_msg, outlen);
    /* 重新配置时先关闭匹配，避免 hook 线程看到半写入的前缀。 */
    g_enabled = 0;
    smp_wmb();
    g_prefix[0] = 0;
    if (copy_prefix(cursor))
        return reply("error: path must stay under /data/local/tmp/\n", out_msg, outlen);
    if (!g_prefix[0])
        return reply("error: empty path\n", out_msg, outlen);
    g_uid = uid;
    smp_wmb();
    g_enabled = 1;
    pr_info("openat-guard-demo: replacement enabled uid=%d prefix=%s\n", g_uid, g_prefix);
    return reply("ok mode=deny\n", out_msg, outlen);
}

static long openat_guard_exit(void *__user reserved)
{
    (void)reserved;
    if (g_hooked)
        unhook_syscalln(__NR_openat, before_openat, 0);
    g_hooked = 0;
    g_enabled = 0;
    return kpm_demo_log_exit("kpm openat-guard-demo");
}

KPM_INIT(openat_guard_init);
KPM_CTL0(openat_guard_control0);
KPM_EXIT(openat_guard_exit);
