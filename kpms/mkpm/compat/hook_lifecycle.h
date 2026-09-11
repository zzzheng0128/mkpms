/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM 卸载期间的 hook 生命周期保护。
 *
 * KernelPatch 当前导出的 hook_unwrap()/fp_hook_unwrap() 在删除最后一项
 * 回调后会立即释放链对象。KPM 的 exit 返回后，模块代码会马上被回收，
 * 而其他 CPU 可能还持有旧的跳板入口；这会把一个正常的卸载变成内核
 * use-after-free。这里保留一个没有回调函数的占位项，让跳板继续存在，
 * 但不再引用本 KPM 的代码。占位项只用于最终的模块 exit 路径，普通的
 * ctl detach/re-attach 仍使用原有 API，不消耗额外槽位。
 */
#ifndef MKPM_HOOK_LIFECYCLE_H
#define MKPM_HOOK_LIFECYCLE_H

#include <hook.h>
#include <syscall.h>
#include <linux/printk.h>

/*
 * 仅用于 KPM_EXIT/初始化失败回滚：
 *   1. 给已有 syscall 链加入 (NULL, NULL) 占位；
 *   2. 移除本模块回调；
 *   3. fp_hook_unwrap() 看到占位后不会释放链。
 *
 * 如果链已经没有可用槽位，仍必须摘掉本模块回调。此时框架可能回收
 * 空链的跳板，但留下模块回调会在 KPM 代码释放后继续跳入悬空地址，
 * 风险更高；调用方会通过日志知道这次没有保住空链。
 */
static inline void mkpm_unhook_syscall_for_exit(int nr, void *before, void *after)
{
    hook_err_t keep = hook_syscalln(nr, 0, 0, 0, 0);
    if (keep != HOOK_NO_ERR && keep != HOOK_DUPLICATED) {
        pr_err("mkpm: cannot reserve syscall %d hook slot before unload: %d\n",
               nr, keep);
        unhook_syscalln(nr, before, after);
        pr_warn("mkpm: syscall %d callback detached without retained trampoline (hook chain full)\n",
                nr);
        return;
    }
    unhook_syscalln(nr, before, after);
    pr_info("mkpm: syscall %d callback detached; trampoline retained for unload safety\n", nr);
}

/* 内联链直接使用公开的 remove=0 变体，清回调但不释放跳板链。 */
static inline void mkpm_unwrap_for_exit(void *func, void *before, void *after)
{
    hook_unwrap_remove(func, before, after, 0);
    pr_info("mkpm: inline hook %px callback detached; trampoline retained for unload safety\n",
            func);
}

#endif /* MKPM_HOOK_LIFECYCLE_H */
