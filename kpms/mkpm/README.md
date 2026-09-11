# mkpm — 合并单 KPM（hide-so + wxshadow + anti-detect + dysvcpit）

目标设备：Pixel 6 (oriole)，Kernel 6.1.99 (GKI)，APatch/KernelPatch root。
一个 `.kpm` 文件提供全部能力：maps/线程隐藏、wxshadow 影子页、系统调用反检测、
supercall 无痕守卫、dysvcpit 六模块（sysmon / ehide / eredirect / evm / emaps / boottime）。

---

## 1. 目录结构

```
kpms/mkpm/
├── main.c                  # 唯一 KPM 入口 + ctl0 分发器（lazy init）
├── CMakeLists.txt
├── compat/
│   ├── kf_string_map.h     # 强制 include：memcpy→kf_memcpy 等宏映射
│   ├── libc_shim.c         # 编译器隐式 emit 的 memcpy/memset 出线定义
│   └── linux/              # KP 内核树缺失的 8 个上游头文件
├── antidetect/
│   ├── antidetect.c        # stat/readlink/getdents64 ENOENT 过滤 + 隐藏名管理
│   └── supercall.c         # supercall 守卫（KP 自身无痕）
├── dysvcpit/
│   ├── sysmon.c            # syscall 监控（attach/preset/start/stop/read）
│   ├── ehide.c             # 文件/dentry 隐藏规则
│   ├── eredirect.c         # 路径重定向规则
│   ├── evm.c               # 事件监控 + dump 日志
│   ├── emaps.c             # /proc/pid/maps 行改写（inode/path 替换、丢弃、追加）
│   └── boottime.c          # 按 UID 改写 CLOCK_BOOTTIME 输出（syscall 113）
└── 引用外部源码：
    ../hide-maps/hidemaps.c # hide-so：maps 块过滤 + 线程名隐藏
    ../wxshadow/*.c         # wxshadow 影子页（5 个文件）
```

约束：合并构建全工程定义 `-DMKPM_MERGED`，只允许 main.c 存在一组
`KPM_INIT/KPM_CTL0/KPM_EXIT` 入口（其余模块的入口宏都被 `#ifndef MKPM_MERGED` 屏蔽）。

---

## 2. 编译（mac → Docker 交叉编译）

环境：Docker 容器 `z-ws`（Ubuntu 24.04 x86_64）+ `aarch64-linux-gnu-gcc` 13.3.0。
容器内源码树 `/tmp/mkpms`，`.kp/kernel` 提供 KP 内核头文件。

### 2.1 同步源码

```bash
cd /Users/freeman/project/douyin/mkpms
tar cf - CMakeLists.txt kpms/mkpm kpms/hide-maps kpms/wxshadow kpms/common \
  | docker exec -i z-ws sh -c 'tar xf - -C /tmp/mkpms'
```

注意：容器 apt 需要清空代理环境变量，否则走死代理 502：
`docker exec -e http_proxy= -e https_proxy= -e HTTP_PROXY= -e HTTPS_PROXY= z-ws apt-get ...`

### 2.2 构建

```bash
docker exec z-ws sh -c 'cd /tmp/mkpms/build-mkpm && \
  cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_BUILD_TYPE=Release .. && \
  make mkpm.kpm'
```

关键编译 flags（根 CMakeLists `add_kpm_module`）：

| flag | 作用 |
|---|---|
| `-ffixed-x18` | **必须**。GKI 内核开 CONFIG_SHADOW_CALL_STACK，x18 是影子栈指针；GCC 默认把 x18 当 scratch，寄存器压力高时分配一次就会导致 panic（见 §6） |
| `-fno-stack-protector -fno-builtin -nostdinc -fno-PIC` | KPM 无 libc 运行时的标准约束 |
| `-mcmodel=large -mno-outline-atomics` | 模块加载地址任意 + GKI 要求 |
| `-include compat/kf_string_map.h` | 源码级 memcpy/memset 绑定到 KP loader 可解析的 kf_* |
| `libc_shim.c` 用 `-D_LINUX_STRING_H_` 单独编译 | 避免与 KP string.h 的 static inline 重定义 |

### 2.3 构建后验证（必做）

```bash
# ① x18 写次数必须为 0
docker exec z-ws sh -c 'aarch64-linux-gnu-objdump -d /tmp/mkpms/build-mkpm/kpms/mkpm/mkpm.kpm \
  | grep -cE "\b(mov|add|sub|adr|adrp|madd|and|orr)\s+x18"'

# ② UND 符号只允许 KP 框架符号（kf_* / kallsyms_* / hook / unhook / compat_* / current_uid 等）
#    出现裸 memcpy/memset/strcpy/snprintf → 加载必失败 "unknown symbol"
#    2026-09-10 实例：main.c / wxshadow.c 漏 include <linux/kernel.h>，
#    snprintf() 退化成裸符号，load 回 EPERM + dmesg "unknown symbol: snprintf"。
#    KP 只绑定 kf_snprintf，所以这两个文件必须拿到 kernel.h 里的
#    `#define snprintf(...) kfunc(snprintf)(...)`；也不要再手写 extern int snprintf(...)。
docker exec z-ws sh -c 'aarch64-linux-gnu-readelf -sW /tmp/mkpms/build-mkpm/kpms/mkpm/mkpm.kpm | grep UND'

# ③ 单一 KPM 入口：__kpm_initcall/__kpm_exitcall/__kpm_ctlmodule 各只有 1 个
docker exec z-ws sh -c 'aarch64-linux-gnu-readelf -sW /tmp/mkpms/build-mkpm/kpms/mkpm/mkpm.kpm | grep __kpm'
```

### 2.4 取回产物

```bash
docker cp z-ws:/tmp/mkpms/build-mkpm/kpms/mkpm/mkpm.kpm dist/mkpm.kpm
```

---

## 3. 加载与控制

```bash
adb push dist/mkpm.kpm /data/local/tmp/mkpm.kpm
adb shell su -c "/data/local/tmp/kpctl load /data/local/tmp/mkpm.kpm amigo123"
adb shell su -c "/data/local/tmp/kpctl list"
adb shell su -c "/data/local/tmp/kpctl control mkpm status"
# 卸载
adb shell su -c "/data/local/tmp/kpctl unload mkpm"
```

- 设备 superkey：`amigo123`（`/data/adb/ap/superkey`）
- ctl0 约定：**返回 rc > 0 kpctl 才打印回复内容**（rc=0 时回复已写但不显示）
- KPM 重启后不自动恢复，需重新 load

### 控制命令总表（`kpctl control mkpm '<cmd>'`）

| 命令 | 说明 |
|---|---|
| `status` | 总状态：`hide=1 wxshadow=1 antidetect=1 sysmon=ready` |
| **hide（hide-so）** | |
| `hide status` | token 列表 + 线程前缀 |
| `hide enable maps` / `hide disable maps` | maps 块过滤开关 |
| `hide token add <s>` / `del <s>` / `list` | 隐藏 token 管理（默认 wwb_） |
| `hide thread-prefix <s>` | 线程名隐藏前缀（默认 wwb-） |
| **wxshadow** | 原 wxshadow 控制命令透传 |
| **antidetect** | |
| `antidetect status` / `enable` / `disable` | 反检测总开关 |
| `antidetect name list` / `add <n>` / `del <n>` / `reset` | 隐藏名管理（8×32B，默认 goldfish_） |
| `antidetect guard on <superkey>` / `off` | supercall 守卫开关 |
| **sysmon（dysvcpit）** | |
| `syscall attach <nr> <narg>` | 挂接单个 syscall；UID/TGID 用独立的 `syscall filter` 设置 |
| `syscall preset io` | 预置挂 io 族（read/write/openat 等 7 个） |
| `syscall start` / `stop` | 启停捕获 |
| `syscall read <off> <count>` | 读事件环（格式化输出） |
| `syscall status` / `detach-all` | 状态 / 全部摘除 |
| **ehide / eredirect / evm / emaps** | 与 dysvcpit 原版命令一致（首词子模块名） |
| `emaps hook` / `unhook` / `addino` / `addpath` / `addboth` / `append` / `drop` / `addpathrxp` / `addpathaddr` / `del` / `clear` / `list` | maps 行改写规则（inode 替换 = addino） |
| `boot uid <uid>` / `time <sec> [msec]` / `status` / `clear` / `off` | 目标 UID 的 `CLOCK_BOOTTIME` 输出偏移；`off` 摘除 syscall hook |

兼容性 demo 的时间/映射对照命令如下。`boot_time` 轮次只对目标 UID 改写
`CLOCK_BOOTTIME` 返回值（减 600 秒），不改系统时钟；`emaps addino` 会把规则目标设为
inode `1`，随后 demo 从 `/proc/self/maps` 读取实际值并报告是否真的改写：

```text
syscall filter uid <app_uid>
syscall attach 113 2
syscall start
syscall read 0 64
syscall stop
syscall detach-all
syscall filter clear

emaps <app_uid> addino rfcompat-mkpm-map 1
emaps <app_uid> hook
emaps <app_uid> list
```

`boot off` 后再次执行 `boot uid ...` 或 `boot time ...` 会自动恢复 syscall hook。合并
KPM 的卸载入口会清空本模块回调并保留无回调的 KernelPatch 跳板链，避免 `fp_hook_unwrap`
和 `hook_unwrap` 释放仍可能被其他 CPU 看到的链对象。兼容 demo 默认跨轮次复用已加载模块；
设置 `KPM_RELOAD=1` 会在应用 force-stop 后验证受保护卸载。显式 reload 会留下少量空链槽位，
长时间反复 reload 前请重启设备。

---

## 4. supercall 守卫（KP 无痕）

hook `__NR_supercall`（45 号），运行在 KP 处理器之后：

- KP 已处理（skip_origin=1）且 caller key hash ≠ 存储的 superkey hash → 覆盖返回 `-ENOENT`
- **例外：key="su" 直接放行**。skip_origin=1 意味着 KP 已经用 uid 白名单验证过调用者
  （apd / APatch 管理器路径）；若不放行，管理器自己的 `kpm list` 也会被 ENOENT，
  表现为"APatch UI 看不到模块/管理器坏掉"。未授权 app 伪造 "su" 会在 KP 自己的
  uid 门槛先失败（skip_origin=0），守卫根本看不到它。
- 未授权 app 连 `SUPERCALL_HELLO` 都探测不到 → KP 存在性隐藏

验证：
```bash
adb shell "KP_SUPERKEY=wrongkey123 /data/local/tmp/kpctl hello"   # 期望: -ENOENT
adb shell "KP_SUPERKEY=amigo123 /data/local/tmp/kpctl hello"      # 期望: hello-ok
adb shell su -c "KP_SUPERKEY=su /data/local/tmp/kpctl hello"      # 期望: hello-ok（管理器路径）
```

---

## 5. 已确认的噪音日志（非故障）

- `packages.list rename: dentry_path_raw failed` — APatch 框架 userd.c 的 rename 钩子
  解析长路径/unhashed dentry 失败的正常噪音，与模块无关。
- panic 现场时间戳相同的大段 KP 日志 — panic 时 KP 回放 boot-log 缓冲区，是历史倾倒不是现场。

---

## 6. 案例：sysmon SP/PC alignment panic（已修复，d304bd6）

**现象**：`kpctl control mkpm 'syscall read 0 6'` 返回 rc=0 后 11µs 内核 panic：
`Internal error: SP/PC alignment exception: 000000008a000000`，pc/lr 垃圾值。

**取证链**（pstore `/sys/fs/pstore/console-ramoops-0`）：
1. `module_control0 ... rc: 0` 已打印 → ctl0 完整返回，崩在下一条 syscall 入口
   （sp 距栈顶仅 448B，普通栈未被踩）
2. x18 = `ffffffeafaa0dff8` = sysmon_after+0x150（模块 .text 区内！）
3. pc = `0x0002006092401a83`、lr = `0x9b00006092401a83`，内含 `0x92401a83`/`0x9b020060`
   = objdump 里 dff0/dff4 处 `and x3,x20,#0x7f` / `madd` 的**指令编码**
   → pc/lr 装的是代码字节，不是地址

**根因**：KPM 构建缺 `-ffixed-x18`。GKI 内核 x18 = 影子调用栈指针；
aarch64-linux-gnu-gcc 寄存器压力高时把 x18 当 scratch（全模块仅 1 处：
sysmon_main 内联 reply_read 的 `adrp x18`）。x18 被踩后，返回路径上任何一次
`scs_pop`（`ldr x30, [x18, #-8]!`）从 .text 装入指令字节 → `ret` 到非对齐垃圾 → panic。

**为什么老模块没事**：hide-so/wxshadow 函数小，从没触发 x18 分配（独立构建验证 0 处）；
mkpm 合并后 sysmon_main（2444B + 3.6KB 栈帧）跨过寄存器压力阈值。

**修复**：
- 根 CMakeLists `add_kpm_module` 加 `-ffixed-x18`（所有模块生效）
- sysmon `reply_copy` 按 outlen 截断并保证 NUL
- sysmon tgid 过滤误用 pid offset → 改 tgid offset
- sysmon_main 返回 reply.len（配合 kpctl rc>0 才打印的约定）

**验证**：新构建 0 处 x18 写；设备上 `preset io → start → 3×read 0 6` 全过无 panic，
回复正常打印；stop/detach-all 正常。

---

## 7. 已知待办

- sysmon g_ring 无锁读写，read 可能读到撕裂事件（良性，未修）
- 重复代码未重构：install_hook/uninstall_hook ×4、eredirect↔emaps 规则引擎、
  wxshadow.c↔wxshadow_bp.c 两个 helper、kfunc 解析散落各模块
- envcheck 集成测试未完成（io-syscall 探针 + rustFrida 注入验证）
- sigsegv-probe / sigsend-probe 是独立观测 KPM，未合并进 mkpm
