# mkpms：KernelPatch/APatch KPM 实验模块

> 新手入口：先看 [DEMO_GUIDE.md](DEMO_GUIDE.md)。里面按 CRC32、openat 返回替换、
> hide 审计和合并模块列出了源码位置、构建路径和 `kpctl` 命令。

本目录用于自有 Pixel/开发机上的 KPM 可用性验证。推荐先构建无副作用的 CRC32 demo，
再验证限定 UID 和测试路径的 openat 返回替换，最后对现有 `mkpm.kpm` 做 hide、
sysmon、wxshadow 或 eredirect 的单项对照。

当前合并分支只把 `mkpm` 作为生产入口；`hide-maps` 和 `wxshadow` 是它引用的源码，
不是独立加载入口。构建约定、Pixel 6 的 `-ffixed-x18` 和产物检查命令写在
[`kpms/mkpm/README.md`](kpms/mkpm/README.md)。

## 原有 wxshadow 说明
利用kpm模块实现kernel中动态切换内存分页，实现应用对内存的读和执行分离，读和执行发生在不同的物理页，使应用读到的是原始物理页，执行的是被hook过的物理页，**从而隐藏hook产生的内存修改**

缺陷：无法对自读代码区域设置断点，同一页无法同时读取和执行

### 目前通过prctl提供接口给用户态进程调用，支持两种接口bp和patch
* wxshadow_client实现了基本的wxshadow接口调用，可以用来测试bp断点和patch能力
* bp接口能够直接对某个地址设置断点，可以用来进行简单的测试无痕效果，设置断点后通过dmesg查看日志
* patch接口可以配合用户态hook框架写入inline hook代码（跳板代码不能存在读取同一页内存的指令），需要用户态工具联调wxshadow提供的接口实现无痕（无法直接对frida等hook框架产生隐藏效果）
* 目前用户态实现hook工具为rustFrida项目，已基本的Java hook和native hook
  
git config submodule.recurse true 自动更新submodule

# 快速使用
* 使用KernelPatch或者Apatch加载kpm模块，wxshadow_client -p pid -a address -r x0=9 -r可选的修改寄存器值，dmesg查看日志  
* 打开测试app，复制value函数的地址，设置断点测试，观察crc校验结果保持不变，修改寄存器改变value函数返回值  
* 复制crc32函数地址设置断点，app卡死，无法同时读取和执行  

<img width="1116" height="173" alt="c62acc29b9c00edf4d3a301c0aacd05a" src="https://github.com/user-attachments/assets/de6280d8-5093-46d3-9fed-db38355ae6f1" />

<img width="585" height="789" alt="d3d3b72fbf1c8d493d2098417def85f2" src="https://github.com/user-attachments/assets/e7be1d78-5d66-4ba7-8dfc-41c8c1f568a3" />

# 更新
* 配合rustfrida实现java、native hook
* https://bbs.kanxue.com/thread-290304.htm#msg_header_h2_5
## 交流群

![wxshadow 微信群](image.png)

## License

This project is licensed under the [GPL v3](LICENSE). Any derivative work that uses, modifies, or distributes this project's code must be open-sourced under the same license.

## 免责声明

本项目仅供安全研究与学习交流使用，**严禁用于任何非法用途**。使用者应遵守所在地区的法律法规，因使用本项目产生的一切后果由使用者自行承担，与项目作者无关。
