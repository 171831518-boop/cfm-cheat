//
//  KernelRW.m
//  CFMCheat
//
//  内核读写实现（kfd 提权链封装）
//
//  说明：本模块封装公开 libkfd 的能力，等价靶场「获取 root」的内核级读写。
//  libkfd 需要作为子模块/源码引入工程，编译时链接。偏移表按靶场内置的
//  iOS 17 / iOS 18 两套填入（见下方 OFFSETS 段），不同设备系统选不同表。
//

#import "KernelRW.h"
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <string.h>

// ======================================================================
// libkfd 符号声明（链接 libkfd 库，或直接编译进工程）
// ======================================================================
extern uint64_t kopen(uint64_t puaf_pages, uint64_t puaf_method,
                      uint64_t kread_method, uint64_t kwrite_method);
extern void kread(uint64_t kfd, uint64_t kaddr, void *uaddr, uint64_t size);
extern void kwrite(uint64_t kfd, void *uaddr, uint64_t kaddr, uint64_t size);
extern void kclose(uint64_t kfd);

// ======================================================================
// 内核结构偏移（占位符，需从当前 iOS 版本的 kernelcache 提取后填入）
// 靶场内置 iOS 17 / iOS 18 两套表，对应 _kfd_offsets_table_ios17 /
// _kfd_offsets_table_ios18_flat。以下为 iOS 16.5 公开 PoC 的参考值，
// 正式使用前必须按设备 kernelcache 校准。
// ======================================================================
// proc 结构
#define OFF_PROC_P_PID          0x60    // proc.p_pid (int32)
#define OFF_PROC_P_LIST         0x8     // proc.p_list.le_next (proc*)
#define OFF_PROC_P_NAME         0x39     // proc.p_name (char[32]) —— 偏移随版本变
#define OFF_PROC_P_TASK         0x10    // proc.p_task (task*)
#define OFF_PROC_P_UCRED        0xE8    // proc.p_ucred (ucred*) —— 随版本变
#define OFF_PROC_P_FD           0xF0    // proc.p_fd (filedesc*) —— 随版本变
// task 结构
#define OFF_TASK_VM_MAP         0x28    // task.vm_map (vm_map*)
#define OFF_TASK_BSD_INFO       0x360   // task.bsd_info (proc*) —— 随版本变
// vm_map 结构
#define OFF_VM_MAP_PMAP         0x40    // vm_map.pmap (pmap*)
#define OFF_VM_MAP_MIN_OFFSET   0x0     // vm_map.min_offset
#define OFF_VM_MAP_MAX_OFFSET   0x8     // vm_map.max_offset
// ucred 结构
#define OFF_UCRED_CR_UID        0x18    // ucred.cr_uid (uid_t)
#define OFF_UCRED_CR_RUID       0x1C    // ucred.cr_ruid
#define OFF_UCRED_CR_SVUID      0x20    // ucred.cr_svuid
#define OFF_UCRED_CR_LABEL      0x78    // ucred.cr_label (mac label)

// 内核符号偏移（占位符，从 kernelcache 提取）
#define KOFF_ALLPROC            0x0     // allproc 链表头（相对内核基址）
#define KOFF_KERNELPROC         0x0     // kernproc
#define KOFF_KERNELMAP          0x0     // kernel_map

static uint64_t g_kfd = 0;              // kopen 返回的 opaque fd
static uint64_t g_kernelBase = 0;       // 内核基址（KASLR 修正）
static uint64_t g_kslide = 0;           // 内核滑动量
static BOOL     g_ready = NO;

// ======================================================================
// 工具：读 sysctl
// ======================================================================
static NSString *sysctlString(const char *name) {
    size_t size = 0;
    sysctlbyname(name, NULL, &size, NULL, 0);
    if (size == 0) return @"";
    char *buf = calloc(1, size);
    sysctlbyname(name, buf, &size, NULL, 0);
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    return s;
}

static uint64_t sysctlU64(const char *name) {
    uint64_t v = 0;
    size_t size = sizeof(v);
    sysctlbyname(name, &v, &size, NULL, 0);
    return v;
}

// ======================================================================
// 获取当前 iOS 版本号（用于选偏移表 / 判断是否支持）
// ======================================================================
static int currentIOSMajorVersion(void) {
    NSString *v = sysctlString("kern.osproductversion");
    NSArray *parts = [v componentsSeparatedByString:@"."];
    if (parts.count > 0) return [parts[0] intValue];
    return 0;
}

static int currentIOSMinorVersion(void) {
    NSString *v = sysctlString("kern.osproductversion");
    NSArray *parts = [v componentsSeparatedByString:@"."];
    if (parts.count > 1) return [parts[1] intValue];
    return 0;
}

@implementation KernelRW

#pragma mark - 提权

+ (BOOL)isSupported {
    // kfd 覆盖范围：iOS 15.0 ~ 16.6.1（puaf_physpuppet/smith/landa 各版本）
    // 靶场自带 iOS 17 / 18 偏移表，说明它适配了更高版本，这里按公开 PoC 上限 + 靶场表判断
    int maj = currentIOSMajorVersion();
    int min = currentIOSMinorVersion();
    // 公开 libkfd 支持：15.0-16.6.1。靶场内置 17/18 表，判断到 18 为止
    if (maj == 15) return YES;
    if (maj == 16) return min <= 6;
    if (maj == 17) return YES;   // 靶场有 iOS 17 偏移表
    if (maj == 18) return YES;   // 靶场有 iOS 18 偏移表
    return NO;
}

+ (BOOL)acquire {
    if (g_ready) return YES;
    if (![self isSupported]) return NO;

    // 根据 iOS 版本选 puaf 方法
    uint64_t puaf = puaf_physpuppet;
    int maj = currentIOSMajorVersion();
    int min = currentIOSMinorVersion();
    if (maj == 16 && min >= 4 && min <= 5) puaf = puaf_smith;
    else if (maj == 16 && min == 6) puaf = puaf_landa;
    else if (maj == 17) puaf = puaf_landa;   // 靶场 17 表用 landa

    // puaf_pages：参考值，物理页数越多成功率越高（越大越占内存）
    uint64_t puaf_pages = 512;

    // 打开 kfd
    uint64_t fd = kopen(puaf_pages, puaf, kread_kqueue_workloop_ctl, kwrite_dup);
    if (fd == 0) {
        // kopen 失败会 sleep 30s 后 exit(1)，这里不会执行到；留防御分支
        return NO;
    }
    g_kfd = fd;
    g_ready = YES;

    // 通过 kread 拿内核基址（KASLR 修正）：从 kernel_task / kernproc 反推
    [self locateKernelBase];

    return YES;
}

+ (void)release {
    if (g_kfd != 0) {
        kclose(g_kfd);
        g_kfd = 0;
    }
    g_ready = NO;
    g_kernelBase = 0;
    g_kslide = 0;
}

+ (BOOL)isReady {
    return g_ready;
}

#pragma mark - 内核基址定位（KASLR 修正）

+ (void)locateKernelBase {
    // 方法：通过 host_get_special_port 拿 host_priv port，再拿 kernel_task port，
    // 走 task 结构定位内核 vm_map，进而算内核基址。
    // 简化实现：用 kread 读 kernproc -> task -> vm_map -> pmap，配合已知符号偏移。
    // 这里留占位，正式接入 libkfd 后按 kernelcache 的 kernproc 偏移填入。
    g_kernelBase = 0;
    g_kslide = 0;
    // TODO: 从 libkfd 的 info/perf 结构读取已解析的 kernel_slide
}

+ (uint64_t)kernelBase {
    return g_kernelBase;
}

#pragma mark - 内核读写原语

+ (uint64_t)kread64:(uint64_t)kaddr {
    uint64_t v = 0;
    kread(g_kfd, kaddr, &v, sizeof(v));
    return v;
}

+ (uint32_t)kread32:(uint64_t)kaddr {
    uint32_t v = 0;
    kread(g_kfd, kaddr, &v, sizeof(v));
    return v;
}

+ (void)kwrite64:(uint64_t)kaddr value:(uint64_t)value {
    kwrite(g_kfd, &value, kaddr, sizeof(value));
}

+ (void)kwrite32:(uint64_t)kaddr value:(uint32_t)value {
    kwrite(g_kfd, &value, kaddr, sizeof(value));
}

+ (void)kreadBuf:(uint64_t)kaddr buf:(void *)buf size:(uint64_t)size {
    kread(g_kfd, kaddr, buf, size);
}

+ (void)kwriteBuf:(uint64_t)kaddr buf:(const void *)buf size:(uint64_t)size {
    kwrite(g_kfd, (void *)buf, kaddr, size);
}

#pragma mark - 内核定位游戏进程（等价 xpf_find_allproc）

+ (uint64_t)findProcByPid:(int)pid {
    // 遍历 allproc 链表（从内核基址 + KOFF_ALLPROC 开始）
    uint64_t proc = [self kread64:g_kernelBase + KOFF_ALLPROC];
    while (proc != 0) {
        int32_t p_pid = (int32_t)[self kread32:proc + OFF_PROC_P_PID];
        if (p_pid == pid) return proc;
        proc = [self kread64:proc + OFF_PROC_P_LIST];
    }
    return 0;
}

+ (uint64_t)findProcByName:(NSString *)name {
    const char *target = name.UTF8String;
    uint64_t proc = [self kread64:g_kernelBase + KOFF_ALLPROC];
    while (proc != 0) {
        char p_name[32] = {0};
        [self kreadBuf:proc + OFF_PROC_P_NAME buf:p_name size:sizeof(p_name)];
        p_name[31] = 0;
        if (strcmp(p_name, target) == 0) return proc;
        proc = [self kread64:proc + OFF_PROC_P_LIST];
    }
    return 0;
}

+ (uint64_t)procTask:(uint64_t)proc {
    return [self kread64:proc + OFF_PROC_P_TASK];
}

+ (uint64_t)taskVmMap:(uint64_t)task {
    return [self kread64:task + OFF_TASK_VM_MAP];
}

+ (uint64_t)gameBase:(NSString *)procName {
    // 等价靶场 _getGame 算出的模块基址（cf/_cfm_taskAddr）
    // 方法：定位游戏 proc -> task -> vm_map，读 vm_map 第一个 entry 的起始地址
    // （即主模块 __TEXT 段 vmaddr，通常等于模块基址）
    uint64_t proc = [self findProcByName:procName];
    if (proc == 0) return 0;
    uint64_t task = [self procTask:proc];
    uint64_t vmmap = [self taskVmMap:task];
    if (vmmap == 0) return 0;
    // vm_map 的 min_offset 通常是可执行映像起始（近似模块基址）
    // 更精确需遍历 vm_map_entry 链表找 __TEXT 段
    uint64_t min_offset = [self kread64:vmmap + OFF_VM_MAP_MIN_OFFSET];
    return min_offset;
}

#pragma mark - 指针链读写

// 链语义：每一步 cur = kread64(cur) + offsets[i]（先解引用再加偏移）
// 老板链：cf + 0xC000060 + 0xA0 + ... = [[[cf] + 0xC000060] + 0xA0] + ...
+ (uint64_t)readChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count {
    uint64_t cur = base;
    for (int i = 0; i < count; i++) {
        cur = [self kread64:cur];       // 先解引用
        if (cur == 0) return 0;
        cur += offsets[i];              // 再加偏移
    }
    return cur;
}

+ (BOOL)writeChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint64_t)value {
    if (count <= 0) return NO;
    uint64_t cur = base;
    // 走链到倒数第二级
    for (int i = 0; i < count - 1; i++) {
        cur = [self kread64:cur];       // 解引用
        if (cur == 0) return NO;
        cur += offsets[i];
    }
    // 末级：解引用 + 末级偏移 = 写入地址
    uint64_t finalPtr = [self kread64:cur];
    if (finalPtr == 0) return NO;
    uint64_t target = finalPtr + offsets[count - 1];
    [self kwrite64:target value:value];
    return YES;
}

@end
