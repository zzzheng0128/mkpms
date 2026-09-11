#ifndef _DEVICE_H_
/* compat shim: KP 不导出 struct device 内部字段。前向声明就够,
 * 真正操作 device 的 API (device_create 等) 通过 kallsyms_lookup_name
 * 调用内核实现。 */
#define _DEVICE_H_
struct device;
#endif