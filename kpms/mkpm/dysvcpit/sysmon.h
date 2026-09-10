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
int sysmon_main(struct opts *opts, char __user *out_msg, int outlen);

#endif /* DYSCVPIT_SYSMON_H */
