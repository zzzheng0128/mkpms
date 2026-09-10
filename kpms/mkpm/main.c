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

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include "../common/kpm_demo_helpers.h"

#include "dysvcpit/opts.h"
#include "dysvcpit/sysmon.h"
#include "dysvcpit/ehide.h"
#include "dysvcpit/eredirect.h"
#include "dysvcpit/evm.h"
#include "dysvcpit/emaps.h"

KPM_MODULE_INFO("mkpm", "1.1.0", "GPL v2", "wwb",
                "Merged KPM: hide-so + wxshadow + anti-detect + dysvcpit (sysmon/ehide/eredirect/evm/emaps)");

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
    if (mkpm_first_is(args, "eredirect")) {
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
    if (mkpm_first_is(args, "antidetect")) {
        if (!mkpm_antidetect_ok)
            return kpm_demo_copy_message("error=antidetect-not-loaded\n", out_msg, outlen);
        return antidetect_control0(args, out_msg, outlen);
    }
    if (mkpm_first_is(args, "status")) {
        char msg[320];

        snprintf(msg, sizeof(msg),
                 "mkpm: hide=%d wxshadow=%d antidetect=%d sysmon=ready ehide=%d eredirect=%d evm=%d emaps=%d\n"
                 "detail: \"hide status\" | \"antidetect status\" | \"syscall status\"\n",
                 mkpm_hide_ok, mkpm_wxshadow_ok, mkpm_antidetect_ok,
                 mkpm_ehide_on, mkpm_eredirect_on, mkpm_evm_on, mkpm_emaps_on);
        return kpm_demo_copy_message(msg, out_msg, outlen);
    }
    return kpm_demo_copy_message(
        "usage: mkpm <subsystem> <args...>\n"
        "  hide:      status|enable [maps|threads]|disable [maps|threads]|token ...|prefix ...|range ...\n"
        "  wxshadow:  (prctl is the real interface; ctl0 is a log stub)\n"
        "  antidetect: status|enable|disable|name list|add <n>|del <n>|reset|guard on <key>|off\n"
        "  syscall:   attach <nr> <narg>|preset io|start|stop|filter ...|read <after> [max]\n"
        "  ehide:     ehide <uid> addprefix|addexact|addtid|del|clear|range ...\n"
        "  eredirect: eredirect <uid> add|del|clear|list ...\n"
        "  evm:       evm <uid> ...\n"
        "  emaps:     emaps <uid> ... (legacy; prefer hide)\n"
        "  status\n",
        out_msg, outlen);

reply_code:
    {
        char msg[64];

        snprintf(msg, sizeof(msg), "%s=%d\n", ret ? "error" : "ok", ret);
        return kpm_demo_copy_message(msg, out_msg, outlen);
    }
}

static long mkpm_exit(void *__user reserved)
{
    (void)reserved;
    if (mkpm_emaps_on)
        emaps_exit();
    if (mkpm_evm_on)
        evm_exit();
    if (mkpm_eredirect_on)
        eredirect_exit();
    if (mkpm_ehide_on)
        ehide_exit();
    sysmon_exit();
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
