/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libc_shim.c - out-of-line memcpy/memset bodies for compiler-emitted calls.
 *
 * GCC emits memcpy/memset calls for struct copies and aggregate zeroing
 * even with -fno-builtin, and some of those generated calls reach the
 * linker as plain UND symbols (the KP loader cannot resolve them on GKI
 * kernels).  This TU provides real global definitions that forward to
 * the KP kfuncs.
 *
 * This file is compiled with -D_LINUX_STRING_H_ (see CMakeLists.txt) so
 * that the force-included kf_string_map.h -> <linux/string.h> expands to
 * nothing here: the static-inline memcpy in string.h would otherwise
 * collide with the global definitions below.  Everything needed is
 * declared by hand; do NOT add KP includes to this file.
 */

/* =====================================================================
 * libc_shim.c - 中文总览
 * =====================================================================
 *
 * 【为什么需要这个文件】
 *   即使编译时加 -fno-builtin, GCC 在做 struct copy / 数组清零时
 *   还是会发 memcpy/memset 调用。这些调用如果走链接器, 会变成
 *   裸的 UND 符号 (memcpy / memset), 而 KP loader 在 GKI 内核上
 *   没法 resolve 这些符号, 模块加载会报 EPERM / "unknown symbol"。
 *
 * 【做法】
 *   1. CMakeLists.txt 用 -include 强制把 kf_string_map.h 放在源文之前:
 *      kf_string_map.h -> #include <linux/string.h> (声明 kf_* kfunc 指针)
 *                       -> #define memcpy kf_memcpy ...
 *      这样编译器把代码里的 memcpy / memset 全部改成 kf_memcpy / kf_memset
 *   2. 但 libc_shim.c 自己又 #undef 掉那些宏, 重新定义全局 memcpy/memset
 *      函数本体, 把它们 forward 到 kf_memcpy/kf_memset。
 *
 * 【避免冲突】
 *   CMakeLists.txt 给 libc_shim.c 设 COMPILE_DEFINITIONS _LINUX_STRING_H_,
 *   让强制-include 的 string.h 变成 no-op, 防止内联 static inline 版本的
 *   memcpy 和我们这里定义的全局 memcpy 冲突。
 *
 * 【为什么这里不 #include KP 头】
 *   libc_shim.c 必须只用最朴素的 typedef + extern kf_*, 不引 KP 头。
 *   否则会被 KP 头里的同名 inline 函数污染, 出现链接期 multiple definition。
 */

typedef unsigned long size_t;

extern void *(*kf_memcpy)(void *dest, const void *src, size_t count);
extern void *(*kf_memset)(void *s, int c, size_t count);
extern void *(*kf_memmove)(void *dest, const void *src, size_t count);
extern int (*kf_memcmp)(const void *cs, const void *ct, size_t count);
extern void *(*kf_memchr)(const void *s, int c, size_t count);

/* undo kf_string_map.h (force-included before this file) */
#undef memcpy
#undef memset
#undef memmove
#undef memcmp
#undef memchr

void *memcpy(void *dest, const void *src, size_t count)
{
    return kf_memcpy(dest, src, count);
}

void *memset(void *s, int c, size_t count)
{
    return kf_memset(s, c, count);
}

void *memmove(void *dest, const void *src, size_t count)
{
    return kf_memmove(dest, src, count);
}

int memcmp(const void *cs, const void *ct, size_t count)
{
    return kf_memcmp(cs, ct, count);
}

void *memchr(const void *s, int c, size_t count)
{
    return kf_memchr(s, c, count);
}
