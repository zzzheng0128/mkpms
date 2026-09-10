/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * sigsegv-probe - observe EL0 execute-permission faults before Android turns
 * them into SIGSEGV/SEGV_ACCERR tombstones.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <ksyms.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("sigsegv-probe",
                "1.0.0",
                "GPL v2",
                "dyidre",
                "Observe user PC/LR/SP/FAR for EL0 execute permission faults");

#define ESR_ELx_EC_SHIFT        26
#define ESR_ELx_EC_MASK         (0x3FUL << ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC(esr)         (((esr) & ESR_ELx_EC_MASK) >> ESR_ELx_EC_SHIFT)
#define ESR_ELx_EC_IABT_LOW     0x20

struct pid_namespace;

static void *g_do_page_fault;
static pid_t (*g_task_pid_nr_ns)(struct task_struct *task,
                                 enum pid_type type,
                                 struct pid_namespace *ns);

static bool sigprobe_is_el0_exec_perm_fault(unsigned int esr)
{
    unsigned int fsc = esr & 0x3f;

    if (ESR_ELx_EC(esr) != ESR_ELx_EC_IABT_LOW)
        return false;

    return (fsc & 0x3c) == 0x0c;
}

static void sigsegv_probe_before(hook_fargs3_t *args, void *udata)
{
    unsigned long far = (unsigned long)args->arg0;
    unsigned int esr = (unsigned int)(unsigned long)args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    struct task_struct *task = current;
    const char *comm;
    pid_t pid = -1;
    pid_t tgid = -1;

    if (!regs || !user_mode(regs))
        return;
    if (!sigprobe_is_el0_exec_perm_fault(esr))
        return;

    if (g_task_pid_nr_ns) {
        pid = g_task_pid_nr_ns(task, PIDTYPE_PID, NULL);
        tgid = g_task_pid_nr_ns(task, PIDTYPE_TGID, NULL);
    }
    comm = get_task_comm(task);

    pr_warn("sigsegv-probe: exec-perm-fault comm=\"%.16s\" pid=%d tgid=%d far=%lx esr=%x pc=%lx lr=%llx sp=%llx pstate=%llx\n",
            comm ? comm : "(null)", pid, tgid, far, esr,
            regs->pc, regs->regs[30], regs->sp, regs->pstate);
}

static long sigsegv_probe_init(const char *args, const char *event,
                               void *__user reserved)
{
    hook_err_t err;

    pr_info("sigsegv-probe: init args=%s event=%s\n",
            args ? args : "(null)", event ? event : "(null)");

    g_task_pid_nr_ns = (typeof(g_task_pid_nr_ns))
        kallsyms_lookup_name("__task_pid_nr_ns");
    g_do_page_fault = (void *)kallsyms_lookup_name("do_page_fault");
    if (!g_do_page_fault)
        g_do_page_fault = (void *)kallsyms_lookup_name("__do_page_fault");
    if (!g_do_page_fault)
        g_do_page_fault = (void *)kallsyms_lookup_name("do_mem_abort");

    if (!g_do_page_fault) {
        pr_err("sigsegv-probe: do_page_fault/do_mem_abort not found\n");
        return -1;
    }

    err = hook_wrap3(g_do_page_fault, sigsegv_probe_before, NULL, NULL);
    if (err) {
        pr_err("sigsegv-probe: hook do_page_fault failed: %d\n", err);
        g_do_page_fault = NULL;
        return err;
    }

    pr_info("sigsegv-probe: hooked fault handler at %px\n", g_do_page_fault);
    return 0;
}

static long sigsegv_probe_control0(const char *args, char *__user out_msg,
                                   int outlen)
{
    return kpm_demo_log_control("sigsegv-probe", args, out_msg, outlen);
}

static long sigsegv_probe_exit(void *__user reserved)
{
    if (g_do_page_fault) {
        hook_unwrap(g_do_page_fault, sigsegv_probe_before, NULL);
        pr_info("sigsegv-probe: unhooked fault handler\n");
        g_do_page_fault = NULL;
    }

    pr_info("sigsegv-probe: exit\n");
    return 0;
}

KPM_INIT(sigsegv_probe_init);
KPM_CTL0(sigsegv_probe_control0);
KPM_EXIT(sigsegv_probe_exit);
