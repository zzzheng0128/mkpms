/* =====================================================================
 * sysmon.h - sysmon (syscall monitor) 子系统头文件
 * =====================================================================
 *
 * 【模块作用】
 *   KPM ctl0 子命令 "syscall ..." 的实现。负责把指定的 syscall 钩起来,
 *   把每次调用的 {nr, args[6], ret, tid/tgid/uid/comm, path} 录到固定
 *   大小的环形 buffer, 再通过 ctl0 read 接口被控制器批量取走。
 *
 * 【与 KP 抽象层的关系】
 *   故意使用 KP 提供的 syscall.h 抽象 (hook_syscalln/unhook_syscalln)
 *   而不是直接摸 kernel 的 syscall_table ABI。前者在老内核上展开为
 *   直接参数路径, 在新内核 (Pixel 6 / GKI) 上展开为 pt_regs wrapper 路径,
 *   调用方对 Pixel 5 / Pixel 6 都是同一套协议。
 *
 * 【对外接口】
 *   sysmon_init()      - 模块加载时调用, 初始化全局状态
 *   sysmon_exit()      - 模块卸载时调用, detach 所有 hook + 清空 ring
 *   sysmon_main(opts)  - ctl0 "syscall ..." 命令分发, 返回值 = 写到
 *                        用户缓冲区的字节数 (kpctl 看到正数会打印出来)
 */
#ifndef DYSCVPIT_SYSMON_H
#define DYSCVPIT_SYSMON_H

#include <compiler.h>

struct opts;

/*
 * KPM ctl0 subcommand: "syscall ...".
 *
 * This module intentionally uses KernelPatch's syscall.h abstraction rather
 * than a kernel-private syscall-table ABI.  That abstraction selects the
 * direct-argument path on older kernels and the pt_regs wrapper path on newer
 * kernels, so the caller has one protocol for both Pixel 5 and Pixel 6.
 */
int sysmon_init(void);
void sysmon_exit(void);
/* 仅供总 KPM 卸载：回调清空后保留空 syscall 跳板链。 */
void sysmon_unload(void);
int sysmon_main(struct opts *opts, char __user *out_msg, int outlen);

#endif /* DYSCVPIT_SYSMON_H */
