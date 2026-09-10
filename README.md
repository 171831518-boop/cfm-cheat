# CFMCheat — 独立外挂 App

照搬 OctopusNote 第四课授权靶场的写法，独立成壳的 CFM 穿越火线手游内存外挂。

核心升级：**免越狱提权**。走 kfd 内核漏洞拿 KRW（内核任意读写），从内核直接读写游戏进程，
**不需要 `task_for_pid`、不需要越狱**，普通机也能用 —— 和靶场「获取 root」是同一套原理。

## 功能

| 功能 | 实现 | 等价靶场 |
|---|---|---|
| 获取 root | kfd 提权拿 KRW（免越狱），回退 setuid（越狱） | xpf + kfd 漏洞链 |
| 开始读写 | KRW 内核定位游戏进程 + 0.1s 循环写值 | freeze_loop |
| 注销设备 | 清授权标志 + 删 plist | 验证标志清零 |
| 红透 | `cf + 0xC000060 + 0xA0 + 0x240 + 0x108 + 0x14C` 写 65536 | versionOffsets 链 |
| 吸附 | `cf + 0xC001DF8 + 0xA0 + 0x70 + 0x1F8` 写 10 | zimiaoOffsets 链 |

## 技术栈（双路线）

| 路线 | 内存读写 | 进程定位 | 前提 |
|---|---|---|---|
| **KernelRW（免越狱）** | kfd `kread/kwrite`（内核任意读写） | 内核 `allproc` 链表定位 proc → task → vm_map | iOS 15.0~18.x + kfd 偏移表 |
| MemoryEngine（越狱） | `task_for_pid` + `mach_vm_read/write` | `mach_vm_region` 遍历找 `__TEXT` | 越狱 + get-task-allow |

`CheatLoop` 优先走 KernelRW，回退 MemoryEngine。

## 指针链语义（关键）

老板给的链是标准**多级指针链**：

```
cf + 0xC000060 + 0xA0 + 0x240 + 0x108 + 0x14C
= [[[[[cf] + 0xC000060] + 0xA0] + 0x240] + 0x108] + 0x14C
```

每一步 `cur = read64(cur) + offset`（先解引用指针，再加偏移），末级写值。已按此语义实现。

## 编译

```
# macOS + Xcode
./build.sh
```

产出 `CFMCheat.ipa`。

## 关键前提（必须读）

### 1. libkfd 必须引入工程才能编译

`KernelRW.m` 调用了 libkfd 的公开 API：

```c
u64 kopen(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method);
void kread(u64 kfd, u64 kaddr, void* uaddr, u64 size);
void kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size);
void kclose(u64 kfd);
```

把公开 kfd PoC 的 `libkfd` 目录（含 `libkfd.h` + 所有 `.c`）拖进 Xcode 工程即可链接。
公开仓库：

- `https://github.com/felix-pb/kfd`（原始，binpwn/kfd 同源）
- `https://github.com/hrtowii/CVE-2023-41974`（landa 变体）
- `https://github.com/opa334/Dopamine`（完整越狱，含最新 kfd 偏移表）

**不引入 libkfd，`KernelRW.m` 会链接报错（`kopen/kread/kwrite` 未定义）。**

### 2. 内核结构偏移必须校准

`KernelRW.m` 顶部的 `OFF_*` / `KOFF_*` 宏是**占位符**，必须从你设备的
kernelcache 提取真实偏移后填入。靶场内置 iOS 17 / iOS 18 两套表，你可以：
- 直接抄靶场 `_kfd_offsets_table_ios17` / `_kfd_offsets_table_ios18_flat` 里的值
- 或用公开工具从 kernelcache 提取（`joker` / `jtool2` / `ipsw` 解包）

涉及的关键偏移：
- `proc.p_pid` / `proc.p_list.le_next` / `proc.p_name` / `proc.p_task`
- `task.vm_map` / `task.bsd_info`
- `vm_map.min_offset` / `vm_map.pmap`
- `allproc` / `kernproc` 内核符号地址（相对内核基址）

### 3. 偏移链是版本相关的

`0xC000060` / `0xC001DF8` 是**特定游戏版本**的基偏移，游戏更新后需重抓。
靶场通过 `DecryptA` 运行时解密偏移字符串得到，独立 App 里直接硬编码即可（改 `CheatLoop.m` 顶部数组）。

### 4. 免越狱 vs 越狱

| 场景 | 生效路线 |
|---|---|
| 普通机（未越狱）+ iOS 15~18 | KernelRW（kfd），点「获取 root」现场打漏洞拿 KRW |
| 越狱机 | 两条都能走，优先 KernelRW，回退 MemoryEngine |

## 文件结构

```
CFMCheat/
├── CFMCheat.xcodeproj/       Xcode 工程
├── CFMCheat/
│   ├── main.m                入口
│   ├── AppDelegate.h/m       应用代理
│   ├── ViewController.h/m    主界面（5 个功能按钮）
│   ├── KernelRW.h/m          ★ 内核读写（kfd 免越狱提权，核心）
│   ├── MemoryEngine.h/m      内存读写引擎（mach 越狱路线）
│   ├── CheatLoop.h/m         每帧循环（双路线）
│   ├── RootHelper.h/m        获取 root（setuid 回退）
│   ├── DeviceManager.h/m     注销设备
│   ├── Info.plist
│   └── CFMCheat.entitlements 签名权限
├── kfd_anchor_map.md         ★ kfd 提权链锚点地图（靶场逆向结论）
└── build.sh                  编译打包脚本
```

## 逆向结论摘要（详见 kfd_anchor_map.md）

靶场的「获取 root」= kfd 内核漏洞链（`posix_spawn` + `icmp6_filter` UAF）拿 KRW，
全程不依赖 `task_for_pid`，所以普通机能用。靶场核心代码被 OLLVM 全量混淆
（CFF 跳转分发器 + MBA 算术 + 指令替换），静态重构不现实，故本工程直接
复用公开 libkfd（与靶场同源），按靶场 iOS 17/18 偏移表适配。
