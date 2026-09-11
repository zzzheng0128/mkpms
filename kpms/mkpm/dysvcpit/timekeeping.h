#pragma once

/* timekeeping.h - KP header 集缺失的内核时间相关 shim
 *
 * 几个 dysvcpit 子系统 (eg evm 的 uptime 统计) 需要 ktime_t / timespec64
 * / KTIME_MAX 等类型和常量, 但 KP header set 没有这些 (KP 想保持精简)。
 * 这里给最小可用定义。
 *
 * 用法: dysvcpit/<module>.c 里 #include "timekeeping.h" 即可。
 *
 * 注意: 真实时间精度依赖 ktime_get_real / ktime_get_boottime 等内核函数,
 * 我们没暴露; 如果以后需要更精确, 把 ktime_get_real 也加进来。
 */

#include <ktypes.h>

typedef __s64 time64_t;
typedef s64 ktime_t;
#define OFFSET_OFFS_BOOT 0x9c
#define CLOCK_BOOTTIME
#define MSEC_PER_SEC 1000L
#define USEC_PER_MSEC    1000L
#define NSEC_PER_USEC    1000L
#define NSEC_PER_MSEC    1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX            ((s64)~((u64)1 << 63))
#define KTIME_MAX            ((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX            (KTIME_MAX / NSEC_PER_SEC)

// #define ns_to_timespec64 impfunc(ns_to_timespec64)
// #define ktime_to_timespec64(kt) ns_to_timespec64((kt))

struct timespec64 {
    time64_t tv_sec;
    long tv_nsec;
};

// struct tk_core_t{
//     struct{
//         unsigned sequence;
//     }seq;
//     u8 timekeeper;
// };

// #define tk_core ((struct tk_core_t *)kallsyms_lookup_name("tk_core"))

// static inline void tk_update_sleep_time(struct timekeeper *tk, ktime_t delta){
//     ktime_t *boot = (ktime_t *)((uintptr_t) tk + OFFSET_OFFS_BOOT);
//     *boot = *boot + delta;
// }

static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs){
    if (unlikely(secs >= KTIME_SEC_MAX))
        return KTIME_MAX;
    return secs * NSEC_PER_SEC + (s64) nsecs;
}

static inline ktime_t timespec64_to_ktime(struct timespec64 ts){
    return ktime_set(ts.tv_sec, ts.tv_nsec);
}