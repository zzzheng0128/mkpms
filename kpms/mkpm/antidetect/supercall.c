/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect-supercall: Require superkey for ALL KernelPatch supercall commands
 *
 * KP's supercall handler (syscall 45) allows HELLO/VER/KLOG etc. without
 * superkey verification — any "su"-auth'd app can probe KP presence.
 *
 * This module adds a guard in the hook chain (runs after KP's handler).
 * If KP processed the call but the key isn't the superkey, we override
 * the result with -ENOENT to mimic truncate(2) failure.
 *
 * Usage: load module with superkey as argument
 *   kpatch kpm load anti-detect.kpm "superkey"
 */

#include "../compat/hook_lifecycle.h"

/* =====================================================================
 * supercall.c - supercall 旁路认证 (superkey guard)
 * =====================================================================
 *
 * 【背景】
 *   KP supercall (syscall 45) 在 KP 内核侧已经做了"caller uid 必须是
 *   manager 或 su-allow" 校验, 但通过后并不再校验 key 本身 — 任何
 *   "su" 字面量 key 都能调 HELLO / VER / KLOG / KPM_LIST 等命令。
 *   也就是说被注入的 target app 一旦拿到 su 权限就能枚举 KP 模块。
 *
 * 【我们的做法】
 *   再挂一个 supercall before-hook, 链路在 KP 自身 before 之后。
 *   只看 KP 已经处理过的 (skip_origin=1) 调用:
 *     - key == "su"  -> 放行 (这是 APatch manager UI 的合法入口)
 *     - hash_key(key) != stored_key_hash -> 把 ret 改成 -ENOENT
 *
 * 【为什么用 hash 不直接 strcmp】
 *   hash_key() 是 scdefs.h 提供的固定算法, KP 内核侧的认证也用同一个
 *   hash 比较, 保证两侧一致。
 *
 * 【未覆盖场景】
 *   真正的 root uid 不通过 su chain 走 supercall (它直接 syscall(45, ..))
 *   这种调用 args->skip_origin=0, 我们的 guard 不拦, 也无需拦 — root
 *   本来就有所有权限。
 *
 * 【关闭方式】
 *   ctl0: "antidetect guard off" 卸载 hook 但保留 hash, 再 "guard on <key>"
 *   可以换 key。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/scdefs.h>

#define MAX_KEY_LEN 128

static long stored_key_hash;
static int hook_installed;

/*
 * Before handler — runs AFTER KP's before() in the chain.
 * If KP handled a supercall (skip_origin=1) and the caller's key
 * doesn't match our stored superkey hash, override result.
 */
static void supercall_guard_before(hook_fargs8_t *args, void *udata)
{
    long ver_xx_cmd = (long)syscall_argn(args, 1);
    long cmd = ver_xx_cmd & 0xFFFF;

    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX)
        return;

    /* Only intercept calls that KP already processed */
    if (!args->skip_origin)
        return;

    const char __user *ukey = (const char __user *)syscall_argn(args, 0);
    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, sizeof(key));

    /* Let "su"-key callers through: skip_origin=1 means KP already vetted
     * the caller uid via is_su_allow_uid (apd / APatch manager path).
     * Overriding here would hide KP from the manager itself and break the
     * UI. Unkeyed apps presenting "su" fail KP's own uid gate first, so
     * skip_origin stays 0 and this guard never sees them. */
    if (len > 0 && key[0] == 's' && key[1] == 'u' && key[2] == '\0')
        return;

    if (len <= 0 || hash_key(key) != stored_key_hash)
        args->ret = -ENOENT;
}

int supercall_guard_is_on(void)
{
    return hook_installed;
}

int supercall_guard_init(const char *superkey)
{
    if (!superkey || !superkey[0]) {
        pr_info("anti-detect: no superkey provided, supercall guard disabled\n");
        return 0;
    }

    if (hook_installed) {
        pr_info("anti-detect: supercall guard already installed\n");
        return 0;
    }

    stored_key_hash = hash_key(superkey);

    hook_err_t err = hook_syscalln(__NR_supercall, 6, supercall_guard_before, 0, 0);
    if (err) {
        pr_err("anti-detect: hook supercall failed: %d\n", err);
        return -1;
    }

    hook_installed = 1;
    pr_info("anti-detect: supercall guard installed\n");
    return 0;
}

void supercall_guard_exit(void)
{
    if (hook_installed) {
        unhook_syscalln(__NR_supercall, supercall_guard_before, 0);
        hook_installed = 0;
        pr_info("anti-detect: supercall guard removed\n");
    }
}

/* 总 KPM 卸载专用：保留空的 syscall 跳板链，避免 fp_hook_unwrap
 * 在最后一个回调移除时立即释放仍可能被其他 CPU 使用的链对象。 */
void supercall_guard_unload(void)
{
    if (hook_installed) {
        mkpm_unhook_syscall_for_exit(__NR_supercall,
                                     supercall_guard_before, 0);
        hook_installed = 0;
        pr_info("anti-detect: supercall guard detached for unload\n");
    }
}
