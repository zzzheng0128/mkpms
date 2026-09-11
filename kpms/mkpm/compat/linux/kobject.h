#ifndef _KOBJECT_H_
/* compat shim: KP 不导出 kobject 结构体定义, 但内核代码通过这个头
 * 引用 struct kobject (eg cdev_init / device_create)。
 * 我们用不到 kobject 内部字段, 只前向声明满足编译即可。 */
#define _KOBJECT_H_
struct kobject;
#endif