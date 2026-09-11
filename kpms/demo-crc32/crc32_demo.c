/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * CRC32 KPM 可用性 demo。
 *
 * 这是一个纯计算模块：不 hook 内核、不改进程内存，只用 ctl0 对一段
 * ASCII 文本计算 CRC32。它适合先验证 KPM 的加载、符号解析、ctl0 返回
 * 和卸载链路，再进入 syscall/HWBP 实验。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "../common/kpm_demo_helpers.h"

KPM_MODULE_INFO("kpm-crc32-demo", "1.0.0", "GPL v2", "rustfrida",
                "KernelPatch CRC32 calculation demo");

static u32 crc32_text(const char *text)
{
    u32 crc = 0xffffffffU;
    size_t i;
    unsigned int bit;

    if (!text)
        return 0;
    for (i = 0; text[i]; i++) {
        crc ^= (u8)text[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return crc ^ 0xffffffffU;
}

static long crc32_reply(const char *message, char *__user out_msg, int outlen)
{
    int len;
    int copied;

    if (!out_msg || outlen <= 0)
        return 0;
    len = strlen(message);
    if (len >= outlen)
        len = outlen - 1;
    copied = compat_copy_to_user(out_msg, message, len + 1);
    if (copied != len + 1)
        return -EFAULT;
    /* kpctl 以 rc>0 判断是否打印 ctl0 回复；返回已写入字符数。 */
    return len;
}

static long crc32_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;
    return kpm_demo_log_init("kpm crc32-demo", event, args);
}

static long crc32_control0(const char *args, char *__user out_msg, int outlen)
{
    const char *text = args;
    char message[256];
    u32 value;

    if (!text || !*text || !strcmp(text, "status"))
        return crc32_reply("usage: calc <text>\n", out_msg, outlen);
    if (!strncmp(text, "calc ", 5))
        text += 5;
    if (!*text)
        return crc32_reply("error: empty text\n", out_msg, outlen);

    value = crc32_text(text);
    snprintf(message, sizeof(message), "crc32=0x%08x text=%s\n", value, text);
    pr_info("crc32-demo: %s", message);
    return crc32_reply(message, out_msg, outlen);
}

static long crc32_exit(void *__user reserved)
{
    (void)reserved;
    return kpm_demo_log_exit("kpm crc32-demo");
}

KPM_INIT(crc32_init);
KPM_CTL0(crc32_control0);
KPM_EXIT(crc32_exit);
