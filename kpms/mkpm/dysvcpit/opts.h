#pragma once
/* opts.h - dysvcpit 子系统 ctl0 命令行解析器
 *
 * 把 ctl0 的 string 命令行 (eg "syscall preset io") 拆成 argv 数组,
 * 所有 dysvcpit 子系统 (sysmon/ehide/emaps/eredirect/evm) 共用同一套解析。
 *
 * 解析特性:
 *   - 以空白字符 (空格 / tab / CR / LF) 分隔 token
 *   - 支持双引号包裹的 token (eg 'name add "qbdi helper"')
 *   - 支持反斜杠转义 (eg 'name add qbdi\\ helper')
 *   - 最多 MAX_OPTS=32 个 token
 *   - 输入限制 OPTS_MAX_IN=4096 字节, 避免无限输入
 *
 * 用法:
 *   struct opts *o = getopt("syscall preset io");
 *   if (o && o->size >= 3 && !strcmp(o->args[1], "preset")) { ... }
 *   free_opts(o);
 */
#define MAX_OPTS 32

struct opts
{
    const char *args[MAX_OPTS];
    int size;
    char *_copy;  /* 内部 malloc 的副本, free_opts 时一并释放 */
};

struct opts *getopt(const char *input);
void free_opts(struct opts *options);