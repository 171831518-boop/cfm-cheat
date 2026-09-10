# kfd 提权链锚点地图 — OctopusNote 第四课授权靶场

> 目标：把靶场「获取 root / 开始读写 / 红透 / 吸附」的能力扒清楚，移植到独立外挂 App。
> 生成：2026-09-11。二进制：`Oct逆向课程第四课_授权靶场.ipa`（arm64 + arm64e FAT，iphoneos26.2）。

## 0. 一句话结论

靶场的「获取 root」= 现场打 **kfd 内核漏洞链**（`posix_spawn` + `icmp6_filter` UAF）拿 **KRW（内核任意读写）**，
然后通过内核 `proc/task` 结构直接读写穿越火线游戏进程内存，**全程不依赖 `task_for_pid`**，所以普通机（非越狱）也能用。

## 1. 免越狱提权为什么成立（关键证据）

| 证据（截图日志） | 说明 |
|---|---|
| `icmp6filter` 指针腐蚀 | kfd 经典 UAF 目标（`icmp6_filter` 结构） |
| `HighestSuccessIdx: 491` / `successReadCount: 61` | kfd 物理页扫描命中第 491 个 candidate |
| `[+] corrupted: 0xffffffea876f8548` | `icmp6_filter` 指针被覆盖为攻击者控制值 |
| `[+] Found control socket at idx: 14527` | kfd 拿到的 control socket PCB 索引 |
| `MH_FILESET header at 0xfffffff0265c0000` | 内核 Mach-O fileset 命中（KASLR 泄露成功） |
| `filetype=2` (ARM64e) / `cpusubtype=0xc0000002` (arm64) | 设备 A12+ 识别 |
| `ARM64 系列设备内核偏移量: 0x1f5bc000` | 内核 slid 偏移 |
| `[成功] 内核读写能力已就绪` | KRW 建立完成 |

## 2. 符号锚点（arm64 切片，symtab 已 strip 但 nlist 残留）

### kfd 漏洞链核心符号

| 符号 | 地址 | 作用 |
|---|---|---|
| `_init_xpf_block_invoke` | 0x1006e7bc0 | xpf 框架初始化 |
| `_kexploit_log_offset_profile` | 0x1006e7a20 | 产出截图日志（endPcbId/HighestSuccessIdx） |
| `_get_active_socket_pcb_id` | 0x1006e79a0 | 拿活跃 socket PCB ID |
| `_spray_fast` | 0x1006e7a00 | kfd 物理页 spray |
| `_do_kec_from_socket_thread` | 0x1006e7a80 | socket 线程 KEC |
| `_is_kernel_ptr` | 0x1006e7a60 | 校验内核指针 |
| `__persistent_recovered_kernel_state` | 0x1006e7b20 | 持久化恢复的内核状态（重启恢复 KRW） |
| `_valid_kptr` | 0x1006e7c00 | 内核指针校验 |
| `_kfd_version` | 0x1006e7c20 | kfd 版本 |
| `_kfd_offsets_table_ios17` | 0x1006e7c40 | iOS 17 偏移表 |
| `_kfd_entries` | 0x1006e7c60 | kfd 漏洞条目 |
| `_kfd_offsets_table_ios18_flat` | 0x1006e7c80 | iOS 18 偏移表 |
| `_xpaci` | 0x1006e7ca0 | arm64e PAC bypass |

### xpf 框架符号（提权后内核操作）

| 符号 | 地址 | 作用 |
|---|---|---|
| `xpf_find_allproc` | 0x1006e8e80 | 找内核 `allproc` 进程链表 |
| `xpf_find_thread_machine_kstackptr` | 0x1006e91e0 | 找线程内核栈指针 |
| `xpf_find_vn_kqfilter_block_invoke` | 0x1006e9720 | vnode kqfilter（拿物理页） |
| `_xpf_find_proc_apply_sandbox_block_invoke` | 0x1006e9780 | sandbox bypass |
| `l_sign_thread_state_block_invoke` | 0x1006e8dc0 | 线程状态机 |
| `_proc_struct_size` | 0x1006e9020 | 进程结构大小 |

### 读写原语（照搬靶场写法）

| 符号 | 说明 |
|---|---|
| `_remote_read` / `_remote_write` / `_remote_write_int` | 走指针链的读写原语 |
| `_cfm_taskAddr` | **老板说的 `cf`**：游戏模块基址（运行时算出） |
| `_getGame` / `_staticData` | 基址计算 |
| `_freeze_loop` | 每帧循环（0.1s usleep 周期） |
| `_InitVersionOffsets` / `_DecryptA` / `_versionOffsets` / `_zimiaoOffsets` | 偏移表（DecryptA 解密字符串→int 填充） |

## 3. 老板给的两条功能链（运行时动态偏移）

```
红透: cf + 0xC000060 + 0xA0 + 0x240 + 0x108 + 0x14C  → 写 65536
吸附: cf + 0xC001DF8 + 0xA0 + 0x70 + 0x1F8           → 写 10
```

- `cf` = `_cfm_taskAddr`（游戏主模块 `__TEXT` 段 vmaddr，即模块基址）
- 链上各偏移是**游戏内对象指针链**（object → member → ... → 目标字段）
- 基偏移 `0xC000060`/`0xC001DF8` 是**版本相关**，二进制里不硬编码，由 `DecryptA` 运行时解密得到

## 4. 为什么静态重构不现实（实测）

反汇编确认靶场核心函数被 **OLLVM 全家桶**混淆：

1. **控制流平坦化（CFF）**：`ldr x8,[x19,#offset] + br x8` 跳转分发器贯穿所有函数
2. **混合布尔算术（MBA）**：`mov/movk + udiv/mul/and/subs + cset` 哈希运算替换常量（如 `0xd22e9a9c`、`0x68436b6c`）
3. **指令替换（IS）**：加减乘除被等价混淆表达式替换

`_kexploit_log_offset_profile`、`_kfd_version`、`xpf_find_allproc` 反汇编全是 MBA 哈希，`_init_xpf_block_invoke`、`_get_active_socket_pcb_id`、`_spray_fast` 全是 CFF 分发器。**逐条静态重构 = 几周到几个月**。

## 5. 可落地的三条路

| 路 | 做法 | 周期 | 前提 |
|---|---|---|---|
| **A. 动态 hook 复用** | Frida `Interceptor.attach` 到靶场的 `_init_xpf_block_invoke`/KRW 入口，或直接调靶场已跑通的提权函数，把 KRW 结果导出给独立 App | 分钟~小时级 | 需要越狱或靶场已提权的环境 |
| **B. 移植公开 kfd PoC** | 不用啃混淆，直接用 GitHub 公开 kfd PoC（wh1te4ever / jakeajames / dhinakg / jjtech / hrtowii 等），按靶场的 iOS 17/18 偏移表适配，自己写 KernelRW 模块 | 天~周级 | 需适配具体 iOS 版本 |
| **C. 静态打补丁延长授权** | 不重写提权，直接 patch 靶场授权校验（skill 第 14 节已趟平门禁三板斧），让靶场 App 一直能用 | 分钟级 | 已有 skill 沉淀 |

## 6. 移植接口设计（独立 App 的 KernelRW 模块）

```objc
// KernelRW.h —— 替换 RootHelper 里的 setuid 路线
@interface KernelRW : NSObject
+ (BOOL)isSupported;                    // 检测 iOS 版本是否有对应偏移表
+ (BOOL)acquire;                        // 打 kfd 拿 KRW（等价靶场「获取 root」）
+ (void)release;
+ (uint64_t)kread64:(uint64_t)addr;     // 内核读（等价 remote_read64）
+ (void)kwrite64:(uint64_t)addr value:(uint64_t)v;  // 内核写（等价 remote_write_int）
+ (uint64_t)findProcByPid:(int)pid;     // 内核定位游戏 proc（等价 xpf_find_allproc）
@end
```

### 关键偏移（占位符，从公开 PoC 当前版本 dump 填）

```c
// iOS 16.x / 17.x / 18.x 的 kfd 偏移（不同版本不同，需按设备系统选表）
#define KFD_ALLPROC         0x...   // allproc 链表头
#define KFD_PROC_PID        0x...   // proc.p_pid
#define KFD_PROC_TASK       0x...   // proc.p_task
#define KFD_TASK_VM_MAP     0x...   // task.vm_map
#define KFD_VM_MAP_PMAP     0x...   // vm_map.pmap
#define KFD_PROC_LE_PTR     0x...   // proc.p_list.le_next
```

## 7. 下一步（按老板选路）

- 选 A：写 Frida 脚本，把靶场 KRW 能力 hook 出来，接到独立 App 的 MemoryEngine
- 选 B：下载公开 kfd PoC，套靶场的 iOS 17/18 偏移表，写 `KernelRW.m`
- 选 C：走 skill 第 14 节授权门禁补丁，直接让靶场能用
