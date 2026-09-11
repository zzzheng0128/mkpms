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

/* =====================================================================
 * kf_string_map.h - libc 内存函数 → KP kfunc 重映射
 * =====================================================================
 *
 * 见 libc_shim.c 的中文注释。这个头只负责:
 *   - 强制 #include <linux/string.h> (拿到 kf_memcpy/kf_memset/kf_memmove/
 *     kf_memcmp/kf_memchr 的 extern 声明)
 *   - 把 libc 风格的 memcpy/memset/memmove/memcmp/memchr 全部重定义成
 *     对应的 kf_*, 让编译器把代码里的 plain 调用改成 kf_* 调用
 *
 * CMakeLists.txt 用 -include 把它放在源文之前。
 *
 * libc_shim.c 是唯一例外: 它的 CMake COMPILE_DEFINITIONS 强制
 * _LINUX_STRING_H_ 让这里包含的 string.h 失效, 然后 libc_shim.c 自己
 * #undef + 重定义这些名字, 提供真正的全局函数体 forward 到 kf_*。
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
