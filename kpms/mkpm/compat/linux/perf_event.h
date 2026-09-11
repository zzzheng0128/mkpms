#ifndef _LINUX_PERF_EVENT_H
/* compat shim: KP 不导出 perf_event 子系统头。
 * mkpm 没用到 perf, 这里只是为了依赖链完整 (一些内核头会包含此头)。 */
#define _LINUX_PERF_EVENT_H

struct perf_event;

#endif