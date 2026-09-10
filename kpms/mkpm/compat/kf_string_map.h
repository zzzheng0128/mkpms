/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kf_string_map.h - map libc-style memory calls onto KernelPatch kfuncs.
 *
 * Must be force-included (-include) BEFORE any source text so that
 * <linux/string.h> is pulled in first (declaring the kf_* kfunc pointers),
 * and only then are the plain names redefined to them.  This keeps
 * compiler-emitted memcpy/memset calls (struct copies, buffer clears)
 * from becoming unresolvable UND symbols in the final .kpm.  The KP
 * loader cannot resolve plain "memcpy"/"memset" on GKI kernels, but
 * binds kf_memcpy/kf_memset from the kpimg kfunc table.
 */
#ifndef MKPM_KF_STRING_MAP_H
#define MKPM_KF_STRING_MAP_H

#include <linux/string.h>

#define memcpy  kf_memcpy
#define memset  kf_memset
#define memmove kf_memmove
#define memcmp  kf_memcmp
#define memchr  kf_memchr

#endif /* MKPM_KF_STRING_MAP_H */
