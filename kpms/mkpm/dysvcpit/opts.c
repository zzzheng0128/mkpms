#include "opts.h"

#include <stddef.h>
#include <linux/string.h>

// #define kmalloc impfunc(__kmalloc)
// #define kfree impfunc(kfree)


#define AT_FDCWD -100
#define AT_NO_AUTOMOUNT 0x800
#define STATX_BASIC_STATS 0x000007ffU

#define __GFP_DMA 0x01u
#define __GFP_HIGHMEM 0x02u
#define __GFP_DMA32 0x04u
#define __GFP_MOVABLE 0x08u
#define __GFP_RECLAIMABLE 0x10u
#define __GFP_HIGH 0x20u
#define __GFP_IO 0x40u
#define __GFP_FS 0x80u
#define __GFP_ZERO 0x100u
#define __GFP_ATOMIC 0x200u
#define __GFP_DIRECT_RECLAIM 0x400u
#define __GFP_KSWAPD_RECLAIM 0x800u
#define __GFP_WRITE 0x1000u
#define __GFP_NOWARN 0x2000u
#define __GFP_RETRY_MAYFAIL 0x4000u
#define __GFP_NOFAIL 0x8000u
#define __GFP_NORETRY 0x10000u
#define __GFP_MEMALLOC 0x20000u
#define __GFP_COMP 0x40000u
#define __GFP_NOMEMALLOC 0x80000u
#define __GFP_HARDWALL 0x100000u
#define __GFP_THISNODE 0x200000u
#define __GFP_ACCOUNT 0x400000u
#define __GFP_NOLOCKDEP 0x800000u

static inline gfp_t get_gfp_atomic(void)
{
	/* All supported P5/P6 kernels satisfy this; keep a typed helper for clang. */
	return __GFP_HIGH;
}

#define __GFP_RECLAIM ((__force gfp_t)(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM))

#define GFP_ATOMIC (__GFP_HIGH | __GFP_ATOMIC | __GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

static void *(*kf___kmalloc)(size_t size, gfp_t flags);
static void (*kf___kfree)(const void *);
static void *(*kf___memset)(void *b, int c, size_t len);
static void (*kf___memcpy)(void *dest, const void *src, size_t count);
static size_t (*kf__strlen)(const char *s);

static inline bool is_space_char(char c){
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static char *skip_spaces_all(char *p){
    while(*p && is_space_char(*p)) p++;
    return p;
}

static void unescape_inplace_simple(char *s){
    char *r = s, *w = s;
    while (*r){
        if (*r == '\\' && r[1]){
            r++;
            *w++ = *r++;
        }else{
            *w++ = *r++;
        }
    }
    *w = '\0';
}

#define OPTS_MAX_IN  4096  // 或者一个合理上限(比如 4096)

struct opts *getopt(const char *input)
{
    if (!input){
        return NULL;
    }
    kf___kmalloc = (void *)kallsyms_lookup_name("__kmalloc");
    kf___kfree = (void*)kallsyms_lookup_name("kfree");
    kf___memset = (void*)kallsyms_lookup_name("memset");
    kf___memcpy = (void*)kallsyms_lookup_name("memcpy");
    kf__strlen = (void*)kallsyms_lookup_name("strlen");

    char *start, *end;
    struct opts *result;
    int i = 0;
    // int len = kf__strlen(input) + 1;
    size_t len = strnlen(input, OPTS_MAX_IN - 1) + 1; // 始终有界

    if (!kf___kmalloc){
        return NULL;
    }
    result = kf___kmalloc(sizeof(struct opts), GFP_KERNEL);
    if (!result){
        return NULL;
    }
    result->_copy = kf___kmalloc(len, GFP_KERNEL);
    if (!result->_copy) {
        kf___kfree(result);
        return NULL;
    }
    kf___memcpy(result->_copy, input, len);
    
    char *p = result->_copy;
    int idx = 0;

    p = skip_spaces_all(p);
    while (*p && idx < MAX_OPTS){
        if (*p == '"'){
            char *beg = ++p; 
            char *q = beg;
            while (*q) {
                if (*q == '"' && q > beg && q[-1] != '\\'){
                    break;
                }
                q++;
            }
            if (*q == '"'){
                *q = '\0';
                unescape_inplace_simple(beg);
                result->args[idx++] = beg;
                p = q + 1;
            }else{
                unescape_inplace_simple(beg);
                result->args[idx++] = beg;
                p = q;
            }
            p = skip_spaces_all(p);
            continue;
        }

        char *beg = p;
        while (*p && !is_space_char(*p)){
            p++;
        }
        if (*p) {
            *p = '\0';
            p++;
        }
        result->args[idx++] = beg;
        p = skip_spaces_all(p);
    }
    result->size = idx;
    return result;
}

void free_opts(struct opts *options)
{
    if (options)
    {
        if (options->_copy)
            kf___kfree(options->_copy);
        kf___kfree(options);
    }
}
