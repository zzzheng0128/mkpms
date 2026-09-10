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
