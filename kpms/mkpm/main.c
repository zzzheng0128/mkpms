/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mkpm - the single merged KernelPatch module.
 *
 * Subsystems (ctl0 first-word dispatch):
 *   hide ...      hide-so: procfs maps/thread hiding.          default ON
 *   wxshadow ...  wxshadow: W^X shadow hidden breakpoints.     default ON
 *   antidetect .. anti-detect: file hiding + supercall guard.  default ON (guard needs key)
 *   syscall ...   sysmon: syscall recorder (dysvcpit).         ready, attach on demand
 *   ehide ...     dysvcpit: per-uid readdir entry hiding.      lazy init on first use
 *   eredirect ... dysvcpit: per-uid open/exec redirect.        lazy init on first use
 *   evm ...       dysvcpit: per-uid vm read/dump.              lazy init on first use
 *   emaps ...     dysvcpit: legacy maps rule hiding.           lazy init (hide-so covers this)
 *   status        combined subsystem status
 *
 * Control path (rustFrida js / shell):
 *   kpatch su kpm control mkpm "hide disable maps"
 *   kpatch su kpm control mkpm "syscall preset io"
 *
 * Not merged: hwbprw/bp/rwmem (/dev/rwmem char device + perf headers missing
 * in the KP header set, and the device node is too easy to detect).
 */

/* =====================================================================
 * mkpm 主入口 — 中文总览
 * =====================================================================
 *
 * 【定位】
 *   mkpm = 单个 .kpm 文件整合 hide-so + wxshadow + anti-detect + dysvcpit
 *   (sysmon/ehide/eredirect/evm/emaps/boottime) 六个子系统。避免在设备上加载多
 *   个 KPM 各自维护 hook 表的复杂度。
 *
 * 【ctl0 命令分发表】
 *   ctl0 args 第一  word 决定路由:
 *     hide ...        转发到 hide_so_control0 (kpms/hide-maps/hidemaps.c)
 *     wxshadow ...    转发到 wxshadow_control (kpms/wxshadow/wxshadow.c)
 *     antidetect ...  转发到 antidetect_control0 (kpms/mkpm/antidetect/)
 *     syscall ...     -> dysvcpit/sysmon.c (sysmon_main)
 *     ehide/eredirect/evm/emaps ...
 *                     懒初始化 + 调 dysvcpit/<module>_main
 *     status          本文件组合打印各子系统状态
 *
 * 【子系统加载顺序 (mkpm_init)】
 *   1. hide_so_init()        — procfs maps/thread 隐藏
 *   2. wxshadow_init()       — W^X shadow 隐藏断点 (Rust-side handler)
 *   3. anti_detect_init()    — 反检测 + supercall guard
 *   4. sysmon_init()         — 录制器就绪, hook 按需挂
 *   5. dysvcpit 五个子系统  — 第一次 ctl0 才 init (懒加载)
 *
 * 【未合并的子系统】
 *   hwbprw / bp / rwmem 没合并进来, 原因:
 *     - /dev/rwmem char device 和 perf headers 在 KP header 集里缺失
 *     - 设备节点本身太容易被检测到, 不利于反检测目标
 *
 * 【编译关键】
 *   CMakeLists.txt 必须加 -ffixed-x18, 否则 GKI (Pixel 6) 内核的 SCS
 *   Shadow Call Stack 指针会被 GCC 当 scratch 寄存器踩掉, sysmon_after
 *   触发 SP/PC alignment exception -> 内核 panic。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
/* Brings the `snprintf -> kfunc(snprintf)` macro. Without it, snprintf() calls
 * emit a bare "snprintf" UND symbol, which the KP loader cannot resolve on GKI
 * kernels -> load fails with EPERM and dmesg says "unknown symbol: snprintf". */
#include <linux/kernel.h>
#include "../common/kpm_demo_helpers.h"

#include "dysvcpit/opts.h"
#include "dysvcpit/sysmon.h"
#include "dysvcpit/ehide.h"
#include "dysvcpit/eredirect.h"
#include "dysvcpit/evm.h"
#include "dysvcpit/emaps.h"
#include "dysvcpit/boottime.h"

KPM_MODULE_INFO("mkpm", "1.1.0", "GPL v2", "wwb",
                "Merged KPM: hide-so + wxshadow + anti-detect + dysvcpit (sysmon/ehide/eredirect/evm/emaps/boottime)");

/* hide-so (hidemaps.c, built with -DMKPM_MERGED) */
extern long hide_so_init(const char *args, const char *event, void *__user reserved);
extern long hide_so_control0(const char *args, char *__user out_msg, int outlen);
extern long hide_so_exit(void *__user reserved);

/* wxshadow (wxshadow.c, built with -DMKPM_MERGED) */
extern long wxshadow_init(const char *args, const char *event, void *__user reserved);
extern long wxshadow_control(const char *args, char *__user out_msg, int outlen);
extern long wxshadow_exit(void *__user reserved);

/* anti-detect (antidetect/, built with -DMKPM_MERGED) */
extern long anti_detect_init(const char *args, const char *event, void *__user reserved);
extern long antidetect_control0(const char *args, char *__user out_msg, int outlen);
extern long anti_detect_exit(void *__user reserved);

static int mkpm_hide_ok;
static int mkpm_wxshadow_ok;
static int mkpm_antidetect_ok;

/* lazy-initialized dysvcpit subsystems */
static int mkpm_ehide_on;
static int mkpm_eredirect_on;
static int mkpm_evm_on;
static int mkpm_emaps_on;
static int mkpm_boottime_on;

static const char *mkpm_rest(const char *args)
{
    const char *p = args;

    if (!p)
        return "";
    while (*p && *p != ' ' && *p != '\t')
        p++;
    while (*p == ' ' || *p == '\t')
        p++;
    return p;
}

/* 跳过两个 token：例如 "redirect 10282 status" -> "status"。 */
static const char *mkpm_rest2(const char *args)
{
    return mkpm_rest(mkpm_rest(args));
}

static int mkpm_first_is(const char *args, const char *word)
{
    int i = 0;

    if (!args)
        return 0;
    while (word[i]) {
        if (args[i] != word[i])
            return 0;
        i++;
    }
    return args[i] == 0 || args[i] == ' ' || args[i] == '\t';
}

/* run a dysvcpit-style <module>_main(opts) with lazy init */
static int mkpm_call_dys(const char *args, int *on, int (*init_fn)(void),
                         int (*main_fn)(struct opts *))
{
    struct opts *opts;
    int ret;

    if (!*on) {
        ret = init_fn();
        if (ret)
            return ret;
        *on = 1;
    }
    opts = getopt(args);
    if (!opts)
        return -12; /* -ENOMEM */
    ret = main_fn(opts);
    free_opts(opts);
    return ret;
}

/* 模块加载入口 (KPM_INIT 宏展开为 .kpm.init section):
 *   1. log init 头
 *   2. 顺序 init hide / wxshadow / anti-detect 三个 always-on 子系统
 *   3. sysmon 只初始化全局状态 (ring + 开关), 不挂 hook
 *   4. 五个 dysvcpit 子系统延迟到首次 ctl0 才 init
 *   5. 任意子系统 init 失败不会中止其它, 标记 *_ok 即可
 */
static long mkpm_init(const char *args, const char *event, void *__user reserved)
{
    long ret;

    kpm_demo_log_init("mkpm", event, args);

    /* hide-so: default ON */
    ret = hide_so_init(args, event, reserved);
    mkpm_hide_ok = (ret == 0);
    if (ret)
        pr_err("mkpm: hide_so_init failed: %ld\n", ret);

    /* wxshadow: default ON */
    ret = wxshadow_init(args, event, reserved);
    mkpm_wxshadow_ok = (ret == 0);
    if (ret)
        pr_err("mkpm: wxshadow_init failed: %ld\n", ret);

    /* anti-detect: default ON; load args double as the supercall-guard key */
    ret = anti_detect_init(args, event, reserved);
    mkpm_antidetect_ok = (ret == 0);
    if (ret)
        pr_err("mkpm: anti_detect_init failed: %ld\n", ret);

    /* sysmon: recorder ready, hooks attach on ctl0 command */
    sysmon_init();

    mkpm_ehide_on = 0;
    mkpm_eredirect_on = 0;
    mkpm_evm_on = 0;
    mkpm_emaps_on = 0;
    mkpm_boottime_on = 0;

    pr_info("mkpm: installed (hide=%d wxshadow=%d sysmon=ready)\n",
            mkpm_hide_ok, mkpm_wxshadow_ok);
    return 0;
}

static long mkpm_control0(const char *args, char *__user out_msg, int outlen)
{
    int ret;

    if (mkpm_first_is(args, "hide")) {
        if (!mkpm_hide_ok)
            return kpm_demo_copy_message("error=hide-not-loaded\n", out_msg, outlen);
        /* hide_so_control0 accepts an optional leading "hide" word */
        return hide_so_control0(args, out_msg, outlen);
    }
    if (mkpm_first_is(args, "syscall")) {
        struct opts *opts;

        opts = getopt(args);
        if (!opts)
            return kpm_demo_copy_message("error=nomem\n", out_msg, outlen);
        ret = sysmon_main(opts, out_msg, outlen);
        free_opts(opts);
        return ret;
    }
    if (mkpm_first_is(args, "wxshadow")) {
        if (!mkpm_wxshadow_ok)
            return kpm_demo_copy_message("error=wxshadow-not-loaded\n", out_msg, outlen);
        return wxshadow_control(mkpm_rest(args), out_msg, outlen);
    }
    if (mkpm_first_is(args, "ehide")) {
        ret = mkpm_call_dys(args, &mkpm_ehide_on, ehide_init, ehide_main);
        goto reply_code;
    }
    /* "redirect" is the short name used by the demo script; keep the
     * historical "eredirect" spelling for existing callers. */
    if (mkpm_first_is(args, "redirect") || mkpm_first_is(args, "eredirect")) {
        if (mkpm_first_is(mkpm_rest2(args), "status")) {
            char msg[160];

            if (!mkpm_eredirect_on) {
                ret = eredirect_init();
                if (ret)
                    return kpm_demo_copy_message("error=redirect-init\n", out_msg, outlen);
                mkpm_eredirect_on = 1;
            }
            ret = eredirect_status(msg, sizeof(msg));
            if (ret < 0)
                return kpm_demo_copy_message("error=redirect-status\n", out_msg, outlen);
            return kpm_demo_copy_message(msg, out_msg, outlen);
        }
        ret = mkpm_call_dys(args, &mkpm_eredirect_on, eredirect_init, eredirect_main);
        goto reply_code;
    }
    if (mkpm_first_is(args, "evm")) {
        ret = mkpm_call_dys(args, &mkpm_evm_on, evm_init, evm_main);
        goto reply_code;
    }
    if (mkpm_first_is(args, "emaps")) {
        ret = mkpm_call_dys(args, &mkpm_emaps_on, emaps_init, emaps_main);
        goto reply_code;
    }
    if (mkpm_first_is(args, "boot") || mkpm_first_is(args, "boottime")) {
        struct opts *opts;
        char msg[256];

        opts = getopt(args);
        if (!opts)
            return kpm_demo_copy_message("error=nomem\n", out_msg, outlen);
        /* status/clear/off 在已经停用的情况下不应重新挂 hook；uid/time
         * 会由 boottime_main() 自己惰性恢复。 */
        if (!mkpm_boottime_on && opts->size >= 2 &&
            strcmp(opts->args[1], "status") &&
            strcmp(opts->args[1], "clear") &&
            strcmp(opts->args[1], "off")) {
            ret = boottime_init();
            if (ret) {
                free_opts(opts);
                return kpm_demo_copy_message("error=boottime-init\n", out_msg, outlen);
            }
            mkpm_boottime_on = 1;
        }
        ret = boottime_main(opts, msg, sizeof(msg));
        if (opts->size >= 2 && !strcmp(opts->args[1], "off"))
            mkpm_boottime_on = 0;
        else if (ret >= 0 && opts->size >= 2 &&
                 (!strcmp(opts->args[1], "uid") ||
                  !strcmp(opts->args[1], "time")))
            mkpm_boottime_on = 1;
        free_opts(opts);
        if (ret < 0)
            return kpm_demo_copy_message("error=boottime-control\n", out_msg, outlen);
        return kpm_demo_copy_message(msg, out_msg, outlen);
    }
    if (mkpm_first_is(args, "antidetect")) {
        if (!mkpm_antidetect_ok)
            return kpm_demo_copy_message("error=antidetect-not-loaded\n", out_msg, outlen);
        return antidetect_control0(args, out_msg, outlen);
    }
    if (mkpm_first_is(args, "status")) {
        char msg[320];

        snprintf(msg, sizeof(msg),
                 "mkpm: hide=%d wxshadow=%d antidetect=%d sysmon=ready ehide=%d eredirect=%d evm=%d emaps=%d boottime=%d\n"
                 "detail: \"hide status\" | \"wxshadow status\" | \"redirect <uid> status\" | \"antidetect status\" | \"syscall status\"\n",
                 mkpm_hide_ok, mkpm_wxshadow_ok, mkpm_antidetect_ok,
                 mkpm_ehide_on, mkpm_eredirect_on, mkpm_evm_on, mkpm_emaps_on, mkpm_boottime_on);
        return kpm_demo_copy_message(msg, out_msg, outlen);
    }
    return kpm_demo_copy_message(
        "usage: mkpm <subsystem> <args...>\n"
        "  hide:      status|enable [maps|threads]|disable [maps|threads]|token ...|prefix ...|range ...\n"
        "  wxshadow:  enable|disable|status (global prctl gate; prctl is the bp interface)\n"
        "  antidetect: status|enable|disable|name list|add <n>|del <n>|reset|guard on <key>|off\n"
        "  syscall:   attach <nr> <narg>|preset io|start|stop|filter ...|read <after> [max]\n"
        "  ehide:     ehide <uid> addprefix|addexact|addtid|del|clear|range ...\n"
        "  redirect:  <uid> addprefix|addexact|del|clear|hook|unhook|print ...\n"
        "  eredirect: alias for redirect (legacy spelling)\n"
        "  evm:       evm <uid> ...\n"
        "  emaps:     emaps <uid> ... (legacy; prefer hide)\n"
        "  boot:      boot uid <uid>|time <sec> [msec]|status|clear|off\n"
        "  status\n",
        out_msg, outlen);

reply_code:
    {
        char msg[64];

        snprintf(msg, sizeof(msg), "%s=%d\n", ret ? "error" : "ok", ret);
        return kpm_demo_copy_message(msg, out_msg, outlen);
    }
}

/* 模块卸载入口 (KPM_EXIT 宏): 严格反向顺序释放。
 * 先关懒加载的 ehide/eredirect/evm/emaps, 再退 sysmon,
 * 再退 anti-detect / wxshadow / hide-so。 */
static long mkpm_exit(void *__user reserved)
{
    (void)reserved;
    if (mkpm_emaps_on)
        emaps_exit();
    if (mkpm_boottime_on)
        boottime_unload();
    if (mkpm_evm_on)
        evm_exit();
    if (mkpm_eredirect_on)
        eredirect_exit();
    if (mkpm_ehide_on)
        ehide_exit();
    sysmon_unload();
    if (mkpm_antidetect_ok)
        anti_detect_exit(reserved);
    if (mkpm_wxshadow_ok)
        wxshadow_exit(reserved);
    if (mkpm_hide_ok)
        hide_so_exit(reserved);
    return kpm_demo_log_exit("mkpm");
}

KPM_INIT(mkpm_init);
KPM_CTL0(mkpm_control0);
KPM_EXIT(mkpm_exit);
