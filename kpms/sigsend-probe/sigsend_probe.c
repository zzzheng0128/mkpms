/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * sigsend-probe - observe userspace attempts to terminate a process with
 * SIGSEGV.  This is intentionally read-only: it never changes syscall args,
 * return values, or skip_origin.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("sigsend-probe",
                "1.0.0",
                "GPL v2",
                "dyidre",
                "Observe SIGSEGV sender syscall context");

#ifndef SIGSEGV
#define SIGSEGV 11
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

struct pid_namespace;

static pid_t (*g_task_pid_nr_ns)(struct task_struct *task,
                                 enum pid_type type,
                                 struct pid_namespace *ns);
static struct task_struct *(*g_find_task_by_vpid)(pid_t nr);
static void (*g_rcu_read_lock)(void);
static void (*g_rcu_read_unlock)(void);

struct syscall_hook {
    int nr;
    int narg;
    void *before;
};

static struct pt_regs *sigsend_syscall_regs(void *args)
{
    if (!has_syscall_wrapper)
        return NULL;
    return (struct pt_regs *)((hook_fargs0_t *)args)->args[0];
}

static void sigsend_current_ids(pid_t *pid, pid_t *tgid)
{
    if (pid)
        *pid = -1;
    if (tgid)
        *tgid = -1;

    if (!g_task_pid_nr_ns)
        return;

    if (pid)
        *pid = g_task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    if (tgid)
        *tgid = g_task_pid_nr_ns(current, PIDTYPE_TGID, NULL);
}

static const char *sigsend_target_comm(pid_t pid)
{
    struct task_struct *task;

    if (!g_find_task_by_vpid || !g_rcu_read_lock || !g_rcu_read_unlock || pid <= 0)
        return "";

    g_rcu_read_lock();
    task = g_find_task_by_vpid(pid);
    g_rcu_read_unlock();

    if (!task)
        return "";

    return get_task_comm(task);
}

static void sigsend_log(void *args, const char *sys_name, int sig,
                        long target0, long target1, long target2)
{
    struct pt_regs *regs = sigsend_syscall_regs(args);
    pid_t sender_pid = -1;
    pid_t sender_tgid = -1;
    uid_t uid = current_uid();
    const char *sender_comm = get_task_comm(current);
    const char *target_comm = sigsend_target_comm((pid_t)target2);

    if (sig != SIGSEGV)
        return;

    sigsend_current_ids(&sender_pid, &sender_tgid);

    pr_warn("sigsend-probe: sig=11 via=%s sender_comm=\"%.16s\" sender_pid=%d sender_tgid=%d uid=%u target0=%ld target1=%ld target2=%ld target_comm=\"%.16s\" user_pc=%lx lr=%llx sp=%llx pstate=%llx\n",
            sys_name ? sys_name : "?",
            sender_comm ? sender_comm : "",
            sender_pid, sender_tgid, uid,
            target0, target1, target2,
            target_comm ? target_comm : "",
            regs ? regs->pc : 0UL,
            regs ? regs->regs[30] : 0ULL,
            regs ? regs->sp : 0ULL,
            regs ? regs->pstate : 0ULL);
}

static void before_kill(hook_fargs2_t *args, void *udata)
{
    long pid = (long)syscall_argn(args, 0);
    int sig = (int)syscall_argn(args, 1);

    sigsend_log(args, "kill", sig, pid, 0, pid);
}

static void before_tkill(hook_fargs2_t *args, void *udata)
{
    long tid = (long)syscall_argn(args, 0);
    int sig = (int)syscall_argn(args, 1);

    sigsend_log(args, "tkill", sig, tid, 0, tid);
}

static void before_tgkill(hook_fargs3_t *args, void *udata)
{
    long tgid = (long)syscall_argn(args, 0);
    long tid = (long)syscall_argn(args, 1);
    int sig = (int)syscall_argn(args, 2);

    sigsend_log(args, "tgkill", sig, tgid, tid, tid);
}

static void before_rt_sigqueueinfo(hook_fargs3_t *args, void *udata)
{
    long pid = (long)syscall_argn(args, 0);
    int sig = (int)syscall_argn(args, 1);

    sigsend_log(args, "rt_sigqueueinfo", sig, pid, 0, pid);
}

static void before_rt_tgsigqueueinfo(hook_fargs4_t *args, void *udata)
{
    long tgid = (long)syscall_argn(args, 0);
    long tid = (long)syscall_argn(args, 1);
    int sig = (int)syscall_argn(args, 2);

    sigsend_log(args, "rt_tgsigqueueinfo", sig, tgid, tid, tid);
}

static void before_pidfd_send_signal(hook_fargs3_t *args, void *udata)
{
    long pidfd = (long)syscall_argn(args, 0);
    int sig = (int)syscall_argn(args, 1);

    sigsend_log(args, "pidfd_send_signal", sig, pidfd, 0, 0);
}

static const struct syscall_hook hooks[] = {
    { __NR_kill,                 2, before_kill },
    { __NR_tkill,                2, before_tkill },
    { __NR_tgkill,               3, before_tgkill },
    { __NR_rt_sigqueueinfo,      3, before_rt_sigqueueinfo },
    { __NR_rt_tgsigqueueinfo,    4, before_rt_tgsigqueueinfo },
    { __NR_pidfd_send_signal,    3, before_pidfd_send_signal },
};

#define NUM_HOOKS (sizeof(hooks) / sizeof(hooks[0]))

static int hooks_installed;

static long sigsend_probe_init(const char *args, const char *event,
                               void *__user reserved)
{
    int i;

    pr_info("sigsend-probe: init args=%s event=%s has_syscall_wrapper=%d\n",
            args ? args : "(null)", event ? event : "(null)",
            has_syscall_wrapper);

    g_task_pid_nr_ns = (typeof(g_task_pid_nr_ns))
        kallsyms_lookup_name("__task_pid_nr_ns");
    g_find_task_by_vpid = (typeof(g_find_task_by_vpid))
        kallsyms_lookup_name("find_task_by_vpid");
    g_rcu_read_lock = (typeof(g_rcu_read_lock))
        kallsyms_lookup_name("rcu_read_lock");
    g_rcu_read_unlock = (typeof(g_rcu_read_unlock))
        kallsyms_lookup_name("rcu_read_unlock");

    for (i = 0; i < (int)NUM_HOOKS; i++) {
        hook_err_t err = hook_syscalln(hooks[i].nr, hooks[i].narg,
                                       hooks[i].before, NULL, NULL);
        if (err) {
            pr_err("sigsend-probe: hook syscall %d failed: %d\n",
                   hooks[i].nr, err);
            goto rollback;
        }
        hooks_installed++;
    }

    pr_info("sigsend-probe: installed %d signal syscall hooks\n",
            hooks_installed);
    return 0;

rollback:
    while (hooks_installed-- > 0)
        unhook_syscalln(hooks[hooks_installed].nr,
                        hooks[hooks_installed].before, NULL);
    hooks_installed = 0;
    return -1;
}

static long sigsend_probe_control0(const char *args, char *__user out_msg,
                                   int outlen)
{
    return kpm_demo_log_control("sigsend-probe", args, out_msg, outlen);
}

static long sigsend_probe_exit(void *__user reserved)
{
    int i;

    for (i = hooks_installed; i-- > 0;)
        unhook_syscalln(hooks[i].nr, hooks[i].before, NULL);
    hooks_installed = 0;

    pr_info("sigsend-probe: exit\n");
    return 0;
}

KPM_INIT(sigsend_probe_init);
KPM_CTL0(sigsend_probe_control0);
KPM_EXIT(sigsend_probe_exit);
