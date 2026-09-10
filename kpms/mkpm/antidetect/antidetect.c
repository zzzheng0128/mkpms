/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * anti-detect: Hide emulator files from apps
 * - Blocks stat/access/readlink with ENOENT
 * - Filters directory listings (getdents64) to remove matching entries
 * - Allows openat (needed for GPU rendering via goldfish_pipe)
 * - Only affects regular apps (uid >= 10000)
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <kallsyms.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include "../../common/kpm_demo_helpers.h"

#ifndef MKPM_MERGED
KPM_MODULE_INFO("anti-detect",
                "1.2.0",
                "GPL v2",
                "wwb",
                "Hide emulator files and KernelPatch presence from apps");
#endif

/* supercall.c */
extern int supercall_guard_init(const char *superkey);
extern void supercall_guard_exit(void);
extern int supercall_guard_is_on(void);

#define AID_APP_START 10000
#define FILENAME_BUF_SIZE 256

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

/* Resolved kernel functions */
static void *(*kfn_kmalloc)(size_t size, unsigned int flags);
static void (*kfn_kfree)(const void *ptr);
static unsigned long (*kfn_copy_from_user)(void *to, const void __user *from, unsigned long n);

/* GFP_KERNEL = 0xcc0 on most kernels */
#define GFP_KERNEL_VAL 0xcc0

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

/* feature switches + manageable hidden-name list (ctl0) */
static int ad_enabled = 1;      /* master switch for file hiding */

#define AD_MAX_NAMES 8
#define AD_NAME_LEN 32
static char ad_name_storage[AD_MAX_NAMES][AD_NAME_LEN];
static const char *hidden_names[AD_MAX_NAMES + 1]; /* NULL-terminated */
static int hidden_name_count;

static void ad_reset_names(void)
{
    hidden_name_count = 0;
    hidden_names[0] = 0;
    kf_memcpy(ad_name_storage[0], "goldfish_", 10);
    hidden_names[0] = ad_name_storage[0];
    hidden_name_count = 1;
    hidden_names[1] = 0;
}

static int ad_add_name(const char *name)
{
    int i;
    size_t len;

    if (!name)
        return -1;
    len = kf_strlen(name);
    if (!len || len >= AD_NAME_LEN)
        return -1;
    for (i = 0; i < hidden_name_count; i++) {
        if (!kf_strcmp(hidden_names[i], name))
            return 0;
    }
    if (hidden_name_count >= AD_MAX_NAMES)
        return -1;
    kf_memcpy(ad_name_storage[hidden_name_count], name, len + 1);
    hidden_names[hidden_name_count] = ad_name_storage[hidden_name_count];
    hidden_name_count++;
    hidden_names[hidden_name_count] = 0;
    return 0;
}

static int ad_del_name(const char *name)
{
    int i, j;

    for (i = 0; i < hidden_name_count; i++) {
        if (kf_strcmp(hidden_names[i], name))
            continue;
        for (j = i; j < hidden_name_count - 1; j++) {
            kf_memcpy(ad_name_storage[j], ad_name_storage[j + 1], AD_NAME_LEN);
            hidden_names[j] = ad_name_storage[j];
        }
        hidden_name_count--;
        hidden_names[hidden_name_count] = 0;
        return 0;
    }
    return -1;
}

static int should_hide(const char *name)
{
    for (const char **p = hidden_names; *p; p++) {
        if (strstr(name, *p))
            return 1;
    }
    return 0;
}

/* Block stat/access/readlink for hidden files */
static void before_stat_syscall(hook_fargs4_t *args, void *udata)
{
    uid_t uid;

    if (!ad_enabled || !hidden_name_count)
        return;
    uid = current_uid();
    if (uid < AID_APP_START) return;

    const char __user *ufilename = (const char __user *)syscall_argn(args, 1);
    char buf[FILENAME_BUF_SIZE];
    long len = compat_strncpy_from_user(buf, ufilename, sizeof(buf));
    if (len <= 0) return;

    if (should_hide(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

/* Pre-scan user dirent buffer for hidden entries without allocating */
static int getdents_has_hidden(char __user *ubuf, long len)
{
    unsigned short reclen;
    char name[FILENAME_BUF_SIZE];
    char __user *pos = ubuf;
    char __user *end = ubuf + len;

    while (pos < end) {
        if (kfn_copy_from_user(&reclen, pos + offsetof(struct linux_dirent64, d_reclen), 2))
            return 0;
        if (reclen == 0 || pos + reclen > end) break;
        long nlen = compat_strncpy_from_user(name, pos + offsetof(struct linux_dirent64, d_name), sizeof(name));
        if (nlen > 0 && should_hide(name))
            return 1;
        pos += reclen;
    }
    return 0;
}

/* Filter directory listings to remove hidden entries */
static void after_getdents64(hook_fargs4_t *args, void *udata)
{
    uid_t uid;
    long ret;
    char __user *ubuf;
    char *kbuf, *src, *end, *dst;
    long new_ret;

    if (!ad_enabled || !hidden_name_count)
        return;
    uid = current_uid();
    if (uid < AID_APP_START) return;

    ret = (long)args->ret;
    if (ret <= 0) return;

    ubuf = (char __user *)syscall_argn(args, 1);

    /* Fast path: no hidden entries, skip allocation entirely */
    if (!getdents_has_hidden(ubuf, ret))
        return;

    /* Skip filtering for huge buffers to avoid unbounded kmalloc */
    if (ret > 256 * 1024)
        return;

    kbuf = kfn_kmalloc(ret, GFP_KERNEL_VAL);
    if (!kbuf) return;

    if (kfn_copy_from_user(kbuf, ubuf, ret)) {
        kfn_kfree(kbuf);
        return;
    }

    src = kbuf;
    end = kbuf + ret;
    dst = kbuf;
    new_ret = 0;

    while (src < end) {
        struct linux_dirent64 *d = (struct linux_dirent64 *)src;
        unsigned short reclen = d->d_reclen;
        if (reclen == 0 || src + reclen > end) break;

        if (!should_hide(d->d_name)) {
            if (dst != src)
                memmove(dst, src, reclen);
            dst += reclen;
            new_ret += reclen;
        }
        src += reclen;
    }

    if (new_ret != ret) {
        if (new_ret == 0 || compat_copy_to_user(ubuf, kbuf, new_ret) == new_ret)
            args->ret = new_ret;
    }

    kfn_kfree(kbuf);
}

static int resolve_symbols(void)
{
    /* kmalloc - try multiple names */
    kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("kmalloc");
    if (!kfn_kmalloc)
        kfn_kmalloc = (typeof(kfn_kmalloc))kallsyms_lookup_name("__kmalloc");
    if (!kfn_kmalloc) {
        pr_err("anti-detect: kmalloc not found\n");
        return -1;
    }

    /* kfree */
    kfn_kfree = (typeof(kfn_kfree))kallsyms_lookup_name("kfree");
    if (!kfn_kfree) {
        pr_err("anti-detect: kfree not found\n");
        return -1;
    }

    /* copy_from_user - try multiple names */
    kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("_copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (typeof(kfn_copy_from_user))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kfn_copy_from_user) {
        pr_err("anti-detect: copy_from_user not found\n");
        return -1;
    }

    pr_info("anti-detect: symbols resolved: kmalloc=%px kfree=%px copy_from_user=%px\n",
            kfn_kmalloc, kfn_kfree, kfn_copy_from_user);
    return 0;
}

struct syscall_hook {
    int nr;
    int narg;
    void *before;
    void *after;
};

static const struct syscall_hook hooks[] = {
    /* stat/access - block with ENOENT */
    { __NR_faccessat,     3, before_stat_syscall, 0 },
    { __NR_faccessat2,    4, before_stat_syscall, 0 },
    { __NR3264_fstatat,   4, before_stat_syscall, 0 },
    { __NR_statx,         5, before_stat_syscall, 0 },
    { __NR_readlinkat,    4, before_stat_syscall, 0 },
    /* getdents64 - filter output */
    { __NR_getdents64,    3, 0, after_getdents64 },
};

#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static int hooks_installed;

#ifdef MKPM_MERGED
long anti_detect_init(const char *args, const char *event, void *__user reserved)
#else
static long anti_detect_init(const char *args, const char *event, void *__user reserved)
#endif
{
    pr_info("anti-detect: loading...\n");

    ad_enabled = 1;
    ad_reset_names();

    if (resolve_symbols())
        return -1;

    for (hooks_installed = 0; hooks_installed < NUM_HOOKS; hooks_installed++) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        hook_err_t err = hook_syscalln(h->nr, h->narg, h->before, h->after, 0);
        if (err) {
            pr_err("anti-detect: hook syscall %d failed: %d\n", h->nr, err);
            goto rollback;
        }
    }

    pr_info("anti-detect: %d hooks installed\n", hooks_installed);

    /* args = superkey for supercall guard (optional) */
    if (supercall_guard_init(args))
        goto rollback_supercall;

    return 0;

rollback_supercall:
    supercall_guard_exit();
rollback:
    while (hooks_installed-- > 0) {
        const struct syscall_hook *h = &hooks[hooks_installed];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    return -1;
}

#ifdef MKPM_MERGED
long anti_detect_exit(void *__user reserved)
#else
static long anti_detect_exit(void *__user reserved)
#endif
{
    supercall_guard_exit();
    int i;
    for (i = NUM_HOOKS; i-- > 0;) {
        const struct syscall_hook *h = &hooks[i];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    pr_info("anti-detect: unloaded\n");
    return 0;
}

/* ---------------------------------------------------------- ctl0 (mkpm) --- */

static int ad_split_args(const char *args, const char **argv, int max_argc)
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

static size_t ad_tok_len(const char *tok)
{
    size_t len = 0;

    while (tok[len] && tok[len] != ' ' && tok[len] != '\t' && tok[len] != '\r' && tok[len] != '\n')
        len++;
    return len;
}

static int ad_tok_eq(const char *tok, size_t len, const char *s)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (!s[i] || s[i] != tok[i])
            return 0;
    }
    return s[len] == 0;
}

static size_t ad_tok_copy(char *dst, size_t cap, const char *tok, size_t len)
{
    if (len >= cap)
        len = cap - 1;
    kf_memcpy(dst, tok, len);
    dst[len] = 0;
    return len;
}

#ifdef MKPM_MERGED
long antidetect_control0(const char *args, char *__user out_msg, int outlen)
#else
static long antidetect_control0(const char *args, char *__user out_msg, int outlen)
#endif
{
    char msg[640];
    const char *argv[8];
    int argc, a0 = 0, off = 0, i;

    argc = ad_split_args(args, argv, 8);
    /* optional leading "antidetect" (mkpm dispatch passes the full string) */
    if (argc > 0 && ad_tok_eq(argv[0], ad_tok_len(argv[0]), "antidetect")) {
        a0 = 1;
        argc--;
    }

#define AD_ARG_IS(n, s) (argc > (n) && ad_tok_eq(argv[(n) + a0], ad_tok_len(argv[(n) + a0]), s))
#define AD_ARG_COPY(n, dst, cap) ad_tok_copy(dst, cap, argv[(n) + a0], ad_tok_len(argv[(n) + a0]))

    if (argc == 0 || AD_ARG_IS(0, "status")) {
        off += kf_snprintf(msg + off, sizeof(msg) - off,
                           "anti-detect: enabled=%d names=%d supercall_guard=%d\n",
                           ad_enabled, hidden_name_count, supercall_guard_is_on());
        for (i = 0; i < hidden_name_count && off < (int)sizeof(msg) - 40; i++)
            off += kf_snprintf(msg + off, sizeof(msg) - off, "name[%d]=%s\n", i, hidden_names[i]);
    } else if (AD_ARG_IS(0, "enable") || AD_ARG_IS(0, "disable")) {
        ad_enabled = AD_ARG_IS(0, "enable");
        off += kf_snprintf(msg + off, sizeof(msg) - off, "ok enabled=%d\n", ad_enabled);
    } else if (AD_ARG_IS(0, "name") && argc >= 2) {
        if (AD_ARG_IS(1, "list")) {
            for (i = 0; i < hidden_name_count && off < (int)sizeof(msg) - 40; i++)
                off += kf_snprintf(msg + off, sizeof(msg) - off, "name[%d]=%s\n", i, hidden_names[i]);
            if (!hidden_name_count)
                off += kf_snprintf(msg + off, sizeof(msg) - off, "(no names)\n");
        } else if (AD_ARG_IS(1, "reset")) {
            ad_reset_names();
            off += kf_snprintf(msg + off, sizeof(msg) - off, "ok names=%d\n", hidden_name_count);
        } else if (argc >= 3 && (AD_ARG_IS(1, "add") || AD_ARG_IS(1, "del"))) {
            char name[AD_NAME_LEN];
            AD_ARG_COPY(2, name, sizeof(name));
            if (AD_ARG_IS(1, "add"))
                off += kf_snprintf(msg + off, sizeof(msg) - off, "%s\n",
                                   ad_add_name(name) ? "error=add" : "ok");
            else
                off += kf_snprintf(msg + off, sizeof(msg) - off, "%s\n",
                                   ad_del_name(name) ? "error=del" : "ok");
        } else {
            off += kf_snprintf(msg + off, sizeof(msg) - off,
                               "error=usage name list|add <n>|del <n>|reset\n");
        }
    } else if (AD_ARG_IS(0, "guard")) {
        if (argc >= 2 && AD_ARG_IS(1, "off")) {
            supercall_guard_exit();
            off += kf_snprintf(msg + off, sizeof(msg) - off, "ok guard=0\n");
        } else if (argc >= 3 && AD_ARG_IS(1, "on")) {
            char key[128];
            AD_ARG_COPY(2, key, sizeof(key));
            off += kf_snprintf(msg + off, sizeof(msg) - off, "%s\n",
                               supercall_guard_init(key) ? "error=guard" : "ok guard=1");
        } else {
            off += kf_snprintf(msg + off, sizeof(msg) - off,
                               "error=usage guard on <superkey>|off\n");
        }
    } else {
        off += kf_snprintf(msg + off, sizeof(msg) - off,
                           "usage: status|enable|disable|name list|add <n>|del <n>|reset|"
                           "guard on <superkey>|off\n");
    }

#undef AD_ARG_IS
#undef AD_ARG_COPY

    pr_info("anti-detect: ctl %s -> %s", args ? args : "(null)", msg);
    return kpm_demo_copy_message(msg, out_msg, outlen);
}

#ifndef MKPM_MERGED
KPM_INIT(anti_detect_init);
KPM_CTL0(antidetect_control0);
KPM_EXIT(anti_detect_exit);
#endif
