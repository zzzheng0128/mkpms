#include <ktypes.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <ktypes.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <compiler.h>
#include <kpmodule.h>

int evm_main(struct opts *opts);
void evm_exit();
int evm_init();