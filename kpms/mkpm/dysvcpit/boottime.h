#pragma once

#include <ktypes.h>
#include "opts.h"

/* CLOCK_BOOTTIME 输出层的 per-UID 演示 hook。 */
int boottime_init(void);
void boottime_exit(void);
/* 仅供总 KPM 卸载：保留 KernelPatch 的空 syscall 跳板链。 */
void boottime_unload(void);
int boottime_main(struct opts *opts, char *out, int outlen);
int boottime_status(char *out, int outlen);
