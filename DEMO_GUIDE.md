# mkpms KPM Demo 指南

这里是 KernelPatch/APatch KPM 的可用性实验入口。先用无副作用模块验证加载、
`ctl0` 回复和卸载，再做 syscall 或页表实验。所有示例只应在自己拥有的开发机、
测试应用和测试路径上运行。

## Demo 对照表

| Demo | 源码 | 做什么 | 默认行为 |
| --- | --- | --- | --- |
| CRC32 | `kpms/demo-crc32/crc32_demo.c` | 对 ctl0 文本计算 CRC32 | 只计算，不 hook |
| openat 返回替换 | `kpms/demo-openat-guard/openat_guard_demo.c` | 对明确 UID+测试路径返回 `-EPERM` | 默认 idle，显式 `deny` 才启用 |
| hide 审计 | `kpms/hide-maps/hidemaps.c` | 现有 procfs maps/线程过滤实现 | 仅查看 status 或 disable 做基线 |
| 合并模块 | `kpms/mkpm/main.c` | hide、wxshadow、sysmon、eredirect 等统一 ctl0 | 生产/历史实验模块，不是入门首个目标 |

顶层 `CMakeLists.txt` 会自动发现新增的 `kpms/*/CMakeLists.txt`，因此新模块会和
其他 KPM 一起生成：

```text
build/kpms/demo-crc32/crc32-demo.kpm
build/kpms/demo-openat-guard/openat-guard-demo.kpm
```

## CRC32 最小实验

加载后用模块控制口计算固定字符串，结果可以和 Python/应用侧 CRC32 对照：

```bash
KPMCTL=/data/adb/ap/bin/apkpm
adb shell su -c "$KPMCTL load /data/local/tmp/crc32-demo.kpm"
adb shell su -c "$KPMCTL control kpm-crc32-demo status"
adb shell su -c "$KPMCTL control kpm-crc32-demo 'calc hello-rustfrida'"
adb shell su -c "$KPMCTL unload kpm-crc32-demo"
```

`calc` 是纯计算路径，适合确认 KPM 的符号解析和回复通道。若当前 `kpctl` 版本
只接受模块文件名作为 control 名称，先用 `kpctl list` 查看实际模块名。

## openat 返回替换实验

`demo-openat-guard` 使用 KP 的 `hook_syscalln(__NR_openat, ...)`，默认只安装 hook，
不打印、不改变返回值。需要验证 before 回调和 `skip_origin` 返回替换时，先为自己
测试应用取 UID，再指定一个测试文件名前缀：

它只依赖 KP 的 syscall hook 抽象，不读取 `task_struct` 或页表的固定偏移；Pixel 5
的 4.19 和 Pixel 6 的 GKI 6.1 都应以各自 `.kp` 头文件重新编译，不能直接混用旧的
`.kpm` 产物。

```bash
adb shell 'cmd package list packages -U com.rustfrida.compatdemo'
KPMCTL=/data/adb/ap/bin/apkpm
adb shell su -c "$KPMCTL control kpm-openat-guard-demo status"
adb shell su -c "$KPMCTL control kpm-openat-guard-demo 'deny <测试UID> /data/local/tmp/rustfrida-openat-demo-'"
adb shell su -c "$KPMCTL control kpm-openat-guard-demo observe"
```

设备上先准备一个普通可读文件，然后用 `demo-openat-guard.js` 触发一次真实的
`FileInputStream`：

```bash
adb shell 'echo mkpms-demo > /data/local/tmp/rustfrida-openat-demo-file; chmod 644 /data/local/tmp/rustfrida-openat-demo-file'
adb push demo-openat-guard.js /data/local/tmp/
rustfrida --pid <目标PID> -l /data/local/tmp/demo-openat-guard.js
```

脚本只验证“允许/拒绝”结果，不修改目标应用代码。路径前缀被模块限制在
`/data/local/tmp/`，避免把实验规则误指到系统路径。

只有匹配的 UID 和绝对路径前缀会返回 `-EPERM`；`observe`/`allow` 会立即停止替换。
不要把规则指向系统路径，实验结束后先执行 `observe`，再卸载模块。这个 demo 不做
路径重定向、不隐藏 maps，也不修改其他 syscall。

合并模块里的 `eredirect` 是另一条路径：它在 `do_filp_open` 层按规则改写目标路径，
用于兼容旧实验。直接控制时使用 `kpctl control mkpm 'eredirect <uid> addexact <from> <to>'`
再执行 `hook`；兼容 demo 的菜单简称为 `redirect`，会自动在同一 App 内做关闭/开启前后
对照。新手优先使用上面的 `demo-openat-guard`，因为它的影响范围更小、卸载更直观。

## hide 现有模块如何审计

`hide-maps` 目前作为源码被合并进 `mkpm.kpm`，没有单独 target；hide 子系统会过滤
procfs maps、map_files 和线程列表。这里不复制或扩展隐藏逻辑；做兼容性审计时按
以下顺序：

```bash
KPMCTL=/data/adb/ap/bin/apkpm
adb shell su -c "$KPMCTL control mkpm 'hide status'"
adb shell su -c "$KPMCTL control mkpm 'hide disable'"
# 记录 /proc/<pid>/maps、/proc/<pid>/task 的基线后再做单项对照
adb shell su -c "$KPMCTL control mkpm 'hide enable'"
adb shell su -c "$KPMCTL control mkpm 'hide enable maps'"
adb shell su -c "$KPMCTL control mkpm 'hide disable maps'"
```

若目标是验证 rustFrida 是否能看到自身映射，保持 hide 关闭，用
`/proc/<pid>/maps` 和 `Module.enumerateModules()` 对账即可。

## compat-demo 集成探针

端到端演示统一放在 `../examples/rustfrida-compat-app`，不依赖其他 Android 项目。
`app/src/main/cpp/native_demo.c` 的 `nativeKpmProbe()` 会触发 raw `svc`、marker
`openat`、`/proc` 读、socket、mmap、短线程和 `CLOCK_BOOTTIME`，并把原始返回值写成
JSON；`test_mkpm_probe.js` 只负责调用这个 JNI 方法。

```bash
bash examples/rustfrida-compat-app/build_demo.sh
bash examples/rustfrida-compat-app/run_demo_spawn.sh 9       # syscall + probe
bash examples/rustfrida-compat-app/run_demo_spawn.sh 11      # hide maps 前后对照
bash examples/rustfrida-compat-app/run_demo_spawn.sh 12      # redirect marker
bash examples/rustfrida-compat-app/run_demo_spawn.sh 13      # CLOCK_BOOTTIME
bash examples/rustfrida-compat-app/run_demo_spawn.sh 14      # emaps inode 替换
bash examples/rustfrida-compat-app/run_demo_spawn.sh 15      # readlink UID 视角隔离
```

唯一入口会自动推送本机 `dyidre/tools/kpctl/kpctl`（可用 `KPCTL_HOST` 覆盖），加载
`mkpm.kpm`，用 `kpctl control mkpm` 切换模块，并在 `runs/compat-demo/<时间戳>/`
保存控制回显、RustFrida 输出和 `SUMMARY.txt`。inode 轮次下发
`emaps addino <uid> rfcompat-mkpm-map 1`，然后由 compat demo 在规则关闭和开启时
分别读取同一进程的 `/proc/self/maps`；摘要显示 `关闭=<原值>，开启=1` 才算改写生效，
不依赖 root shell 读取已经被探针释放的临时 VMA。redirect 轮次同样先确认关闭时
`open=-2`，再确认开启后读到 `mkpm-redirect-target`。boot_time 轮次对目标 UID 的
`CLOCK_BOOTTIME` 输出减 600 秒，root shell 读取 `/proc/uptime` 作对照；全局系统时钟
不变。readlink 轮次在应用私有目录创建 symlink，目标 UID 应得到 `ENOENT`，root shell
应读到原始目标。Pixel6 上 runner 默认复用已加载 KPM，修改 KPM 后重启设备再加载；
合并模块的 exit 路径会先停止演示进程，再清空本模块回调并保留无回调跳板；可以用
`KPM_RELOAD=1` 做受控卸载回归。反复多轮显式 reload 会积累少量空链槽位，长时间压测后重启设备。

## 构建和验证

macOS 上推荐使用现有 Docker 交叉编译环境，详细编译约定仍以
`kpms/mkpm/README.md` 为准。构建后至少检查：

```bash
aarch64-linux-gnu-readelf -sW <module>.kpm | grep __kpm
aarch64-linux-gnu-readelf -sW <module>.kpm | grep UND
```

每个独立 demo 都应该只出现一组 init/ctl0/exit 入口，UND 符号不能出现裸的
`memcpy`、`memset`、`snprintf`。Pixel 6 GKI 还必须保留根 CMake 中的
`-ffixed-x18`，否则高寄存器压力的 KPM 可能破坏 Shadow Call Stack。
