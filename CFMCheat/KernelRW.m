//
//  KernelRW.m
//  CFMCheat
//
//  内核读写实现（kfd 提权链封装）v2
//
//  v1 的问题（老板实测"点获取 root 就卡死"）：
//   1. acquire 在主线程同步跑 exploit —— kfd 的 spray/scan 要几秒到几十秒，UI 冻死
//   2. iOS 版本不在 libkfd 的 kern_versions 表内时，info_init 直接
//      assert_false("unsupported osversion") -> sleep(30) + exit(1) -> 卡 30 秒闪退
//   3. 内核结构偏移全是占位符，就算提权成功 allproc 遍历也是读垃圾
//   4. 用 kwrite 直接写游戏用户态地址 —— 用户态地址只在目标进程地址空间有效，
//      必须经 pmap 页表翻译成物理地址，物理地址再转内核虚拟地址（physmap）
//
//  v2 全部修正。偏移来源：
//   - info.kaddr.*      : libkfd 运行时解析好的内核地址
//   - dynamic_info.*    : 按当前内核版本匹配的结构偏移（p_pid/p_list/task__map...）
//   - perf.*            : gVirtBase/gPhysBase（phys->virt 翻译）
//   - p_task / map->pmap / pmap->ttbr 三个偏移运行时自推导：
//     用自己的 proc/task/map/pmap 已知值扫描自身结构 + 翻译自校验（哨兵值读回）
//

#import "KernelRW.h"
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <string.h>
#import <stdlib.h>
#import <dispatch/dispatch.h>

// ======================================================================
// libkfd 符号（实现编在 kfd_shim.c 里）
// ======================================================================
extern uint64_t kopen(uint64_t puaf_pages, uint64_t puaf_method,
                      uint64_t kread_method, uint64_t kwrite_method);
extern void kread(uint64_t kfd, uint64_t kaddr, void *uaddr, uint64_t size);
extern void kwrite(uint64_t kfd, void *uaddr, uint64_t kaddr, uint64_t size);
extern void kclose(uint64_t kfd);

// kfd_shim.c 的 C 访问器
extern uint64_t cfm_kfd_info_kaddr(uint64_t kfdh, int which);
extern uint64_t cfm_kfd_dyn(uint64_t kfdh, int field);
extern uint64_t cfm_kfd_perf(uint64_t kfdh, int which);
extern uint64_t cfm_kfd_version_count(void);
extern const char* cfm_kfd_version_string(uint64_t i);
extern uint64_t cfm_kfd_version_kread_kqueue_supported(uint64_t i);
extern uint64_t cfm_vmmap_first_entry_offset(void);
extern uint64_t cfm_vmmap_min_offset(void);
extern uint64_t cfm_vmmap_pmap_offset(void);
extern int  cfm_kfd_panic_happened(void);
extern void cfm_kfd_panic_reset(void);

// info.kaddr 索引（与 shim 侧一致）
enum {
    KI_CURRENT_MAP = 0, KI_CURRENT_PMAP,
    KI_CURRENT_PROC, KI_CURRENT_TASK,
    KI_KERNEL_PROC, KI_KERNEL_TASK,
};
// dynamic_info 索引
enum {
    KD_PROC_PID = 0, KD_PROC_LE_PREV, KD_TASK_MAP, KD_PROC_OBJ_SIZE,
};
enum { KPERF_SLIDE = 0, KPERF_GVIRTBASE, KPERF_GPHYSBASE };

// ======================================================================
// 状态
// ======================================================================
static uint64_t g_kfd = 0;              // kopen 返回的 struct kfd*
static BOOL     g_ready = NO;
static BOOL     g_acquiring = NO;

// 运行时自推导的偏移（0 = 未推导）
static uint64_t g_offProcTask = 0;      // proc -> task 指针字段偏移
static uint64_t g_offMapPmap  = 0;      // vm_map -> pmap 偏移（预期 0x38）
static uint64_t g_offPmapTTBR = 0;      // pmap -> ttbr（用户页表基址）偏移
static uint64_t g_physmapBase = 0;      // kva = pa + g_physmapBase

// 游戏进程缓存
int g_cfm_game_pid  = 0;                // 最近定位到的游戏 pid
static uint64_t g_gameTTBR = 0;         // 游戏 pmap 的 ttbr（页表基址缓存）

// ARM64 16KB granule，48-bit VA，4 级页表（xnu T1SZ=16）
#define PA_MASK      0x0000FFFFFFFFC000ULL   // 描述符输出物理地址位 [47:14]
#define PHYSMAP_FALL 0xFFFFFFF000000000ULL   // iOS 15/16 physmap 基址（perf 没给时兜底）
#define KPTR_MIN     0xFFFFFE0000000000ULL   // 内核指针下界（启发式）

// 自校验哨兵：翻译自己的这个变量来验证整条翻译链
static volatile uint64_t g_selftest = 0x43464D54455354ULL; // "CFMTEST"

// ======================================================================
// 工具
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

static uint64_t pa2kva(uint64_t pa) {
    return g_physmapBase ? (pa + g_physmapBase) : (pa + PHYSMAP_FALL);
}

static BOOL descPlausible(uint64_t desc) {
    if ((desc & 3) == 0) return NO;              // invalid
    if ((desc & PA_MASK) == 0) return NO;        // pa 为 0
    if ((desc >> 48) != 0) return NO;            // 高位脏数据
    return YES;
}

@implementation KernelRW

#pragma mark - 支持性预检

+ (NSString *)supportError {
    // 与 libkfd info_init 完全相同的匹配逻辑：kern.version 前缀匹配版本表
    char kv[512] = {0};
    size_t sz = sizeof(kv);
    if (sysctlbyname("kern.version", kv, &sz, NULL, 0) != 0) {
        return @"无法读取内核版本（kern.version）";
    }
    size_t n = cfm_kfd_version_count();
    for (size_t i = 0; i < n; i++) {
        const char *t = cfm_kfd_version_string(i);
        if (strlen(t) > 0 && strncmp(kv, t, strlen(t)) == 0) {
            return nil;   // 命中，支持
        }
    }
    NSString *ver = [NSString stringWithUTF8String:kv];
    ver = [ver componentsSeparatedByString:@"\n"].firstObject ?: ver;
    return [NSString stringWithFormat:
        @"当前内核不在公开 kfd 支持表内（%@）。\n"
         "公开 kfd 仅支持特定机型的 iOS 15.0~16.6.1；\n"
         "iOS 17/18 需要靶场内置的私有偏移表，公开源码没有。", ver];
}

+ (BOOL)isSupported {
    return [self supportError] == nil;
}

#pragma mark - 提权（后台线程）

+ (void)acquireWithProgress:(void(^)(NSString *msg))progress
                 completion:(void(^)(BOOL ok, NSString *msg))completion {
    if (g_ready) {
        if (completion) completion(YES, @"root 已获取（KRW 就绪）");
        return;
    }
    if (g_acquiring) {
        if (completion) completion(NO, @"提权进行中，请等待");
        return;
    }
    NSString *err = [self supportError];
    if (err) {
        if (completion) completion(NO, err);
        return;
    }

    g_acquiring = YES;
    cfm_kfd_panic_reset();

    void (^progressMain)(NSString *) = ^(NSString *m) {
        if (progress) dispatch_async(dispatch_get_main_queue(), ^{ progress(m); });
    };
    void (^doneMain)(BOOL, NSString *) = ^(BOOL ok, NSString *m) {
        g_acquiring = NO;
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(ok, m); });
    };

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        progressMain(@"正在匹配内核版本偏移表…");

        // kread 方法按版本表的支持位选（16.5/16.6 必须 sem_open）
        uint64_t kread_m = kread_kqueue_workloop_ctl;
        {
            char kv[512] = {0};
            size_t sz = sizeof(kv);
            if (sysctlbyname("kern.version", kv, &sz, NULL, 0) == 0) {
                size_t n = cfm_kfd_version_count();
                for (size_t i = 0; i < n; i++) {
                    const char *t = cfm_kfd_version_string(i);
                    if (strlen(t) > 0 && strncmp(kv, t, strlen(t)) == 0) {
                        if (!cfm_kfd_version_kread_kqueue_supported(i)) {
                            kread_m = kread_sem_open;
                        }
                        break;
                    }
                }
            }
        }

        // puaf 方法按大版本选：15/16.0-16.3 physpuppet，16.4-16.5 smith，16.6 landa
        NSString *osv = sysctlString("kern.osproductversion");
        NSArray *parts = [osv componentsSeparatedByString:@"."];
        int maj = parts.count > 0 ? [parts[0] intValue] : 0;
        int min = parts.count > 1 ? [parts[1] intValue] : 0;
        uint64_t puaf;
        if (maj < 16 || min <= 3)      puaf = puaf_physpuppet;
        else if (min <= 5)             puaf = puaf_smith;
        else                           puaf = puaf_landa;

        progressMain(@"正在打 kfd 内核漏洞（物理页 spray + 扫描，需要几秒到几十秒）…");

        uint64_t fd = kopen(400, puaf, kread_m, kwrite_dup);

        if (fd == 0 || cfm_kfd_panic_happened()) {
            cfm_kfd_panic_reset();
            doneMain(NO, @"kfd exploit 失败（漏洞触发不成功，内核状态已回滚尝试）");
            return;
        }

        g_kfd = fd;

        progressMain(@"exploit 成功，正在自检内核读写…");

        // 自检：读自己 proc 的 pid
        uint64_t curProc = cfm_kfd_info_kaddr(g_kfd, KI_CURRENT_PROC);
        uint64_t pidOff  = cfm_kfd_dyn(g_kfd, KD_PROC_PID);
        int32_t mypid = 0;
        kread(g_kfd, curProc + pidOff, &mypid, sizeof(mypid));
        if (mypid != getpid()) {
            doneMain(NO, @"内核读自检失败（pid 不匹配）");
            return;
        }

        progressMain(@"正在推导内核结构偏移…");
        if (![self deriveStructOffsetsWithProgress:progressMain]) {
            doneMain(NO, @"结构偏移推导失败（机型不在预期范围）");
            return;
        }

        g_ready = YES;
        doneMain(YES, @"root 已获取（kfd 内核读写就绪）");
    });
}

+ (BOOL)acquire {
    // 兼容旧同步 API（内部走异步等完成）—— 调试用，不要在主线程调
    if (g_ready) return YES;
    __block BOOL ok = NO;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self acquireWithProgress:nil
                   completion:^(BOOL good, NSString *msg) {
                       ok = good;
                       dispatch_semaphore_signal(sem);
                   }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return ok;
}

+ (void)teardown {
    if (g_kfd != 0) {
        kclose(g_kfd);
        g_kfd = 0;
    }
    g_ready = NO;
    g_offProcTask = 0;
    g_offMapPmap = 0;
    g_offPmapTTBR = 0;
    g_physmapBase = 0;
    g_gameTTBR = 0;
    g_cfm_game_pid = 0;
}

+ (BOOL)isReady {
    return g_ready;
}

#pragma mark - 结构偏移运行时推导

+ (BOOL)deriveStructOffsetsWithProgress:(void(^)(NSString *))progress {
    uint64_t objSize  = cfm_kfd_dyn(g_kfd, KD_PROC_OBJ_SIZE);
    uint64_t curProc  = cfm_kfd_info_kaddr(g_kfd, KI_CURRENT_PROC);
    uint64_t curTask  = cfm_kfd_info_kaddr(g_kfd, KI_CURRENT_TASK);
    uint64_t curMap   = cfm_kfd_info_kaddr(g_kfd, KI_CURRENT_MAP);
    uint64_t curPmap  = cfm_kfd_info_kaddr(g_kfd, KI_CURRENT_PMAP);
    if (!curProc || !curTask || !curMap || !curPmap || objSize == 0) return NO;

    // --- physmap 基址候选：优先 perf 解析值，兜底 iOS15/16 常量 ---
    uint64_t gv = cfm_kfd_perf(g_kfd, KPERF_GVIRTBASE);
    uint64_t gp = cfm_kfd_perf(g_kfd, KPERF_GPHYSBASE);
    uint64_t physCandidates[2];
    int nphys = 0;
    if (gv && gp && gv > gp) physCandidates[nphys++] = gv - gp;
    physCandidates[nphys++] = PHYSMAP_FALL;

    // --- 1. proc->task 偏移：扫自己 proc 结构找 current_task 值 ---
    {
        uint8_t *buf = malloc(objSize);
        if (!buf) return NO;
        kread(g_kfd, curProc, buf, objSize);
        g_offProcTask = 0;
        for (uint64_t off = 0; off + 8 <= objSize; off += 8) {
            uint64_t v;
            memcpy(&v, buf + off, 8);
            if (v == curTask) { g_offProcTask = off; break; }
        }
        free(buf);
        if (g_offProcTask == 0) return NO;
    }

    // --- 2. vm_map->pmap 偏移：扫自己 vm_map 找 current_pmap 值 ---
    {
        uint8_t buf[0x60];
        kread(g_kfd, curMap, buf, sizeof(buf));
        g_offMapPmap = cfm_vmmap_pmap_offset();   // 默认 0x38
        for (uint64_t off = 0; off + 8 <= sizeof(buf); off += 8) {
            uint64_t v;
            memcpy(&v, buf + off, 8);
            if (v == curPmap) { g_offMapPmap = off; break; }
        }
    }

    // --- 3. pmap->ttbr 偏移 + physmap 基址：翻译自校验 ---
    {
        uint8_t pbuf[0x40];
        kread(g_kfd, curPmap, pbuf, sizeof(pbuf));
        uint64_t selfVA = (uint64_t)&g_selftest;

        for (uint64_t off = 0; off + 8 <= sizeof(pbuf); off += 8) {
            uint64_t cand;
            memcpy(&cand, pbuf + off, 8);
            if (cand == 0 || (cand >> 48) != 0) continue;
            uint64_t ttbr = cand & PA_MASK;
            if (ttbr == 0) continue;

            for (int p = 0; p < nphys; p++) {
                g_physmapBase = physCandidates[p];
                uint64_t pa = [self translateVA:selfVA ttbr:ttbr];
                if (pa != 0) {
                    uint64_t back = 0;
                    kread(g_kfd, pa, &back, 8);
                    if (back == g_selftest) {
                        g_offPmapTTBR = off;
                        progress([NSString stringWithFormat:
                            @"偏移推导完成: p_task=0x%llx map->pmap=0x%llx pmap->ttbr=0x%llx",
                            g_offProcTask, g_offMapPmap, g_offPmapTTBR]);
                        return YES;
                    }
                }
                g_physmapBase = 0;
            }
        }
        g_physmapBase = 0;
        return NO;
    }
}

// ARM64 16KB granule 4 级页表走表：VA -> PA（0 = 未映射/走表失败）
// 层级索引（48-bit VA）：L0=[47]  L1=[46:36]  L2=[35:25]  L3=[24:14]  页内偏移=[13:0]
+ (uint64_t)translateVA:(uint64_t)va ttbr:(uint64_t)ttbr {
    uint64_t table = ttbr;
    const int shifts[4] = { 47, 36, 25, 14 };
    for (int level = 0; level < 4; level++) {
        uint64_t desc = 0;
        uint64_t descKVA = pa2kva(table) + (((va >> shifts[level]) & 0x7FF) * 8);
        kread(g_kfd, descKVA, &desc, 8);
        if (!descPlausible(desc)) return 0;

        uint64_t next = desc & PA_MASK;
        if (level == 3) {
            if ((desc & 3) != 3) return 0;        // L3 必须是页描述符
            return next | (va & 0x3FFF);
        }
        if ((desc & 3) == 1) {
            // L1/L2 block 描述符：块大小 = 2^shifts[level]
            //   L1 block = 2^36 (64GB), L2 block = 2^25 (32MB)
            uint64_t blockSize = 1ULL << shifts[level];
            return next | (va & (blockSize - 1));
        }
        // table 描述符（(desc & 3) == 3）：进入下一级
        table = next;
    }
    return 0;
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

#pragma mark - 内核定位游戏进程

+ (int)findGamePidByName:(NSString *)name {
    // sysctl KERN_PROC_ALL 列进程，p_comm 前缀匹配
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0) return 0;

    len += 16 * sizeof(struct kinfo_proc);   // 余量：进程数在变
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return 0;
    if (sysctl(mib, 3, procs, &len, NULL, 0) != 0) {
        free(procs);
        return 0;
    }

    int result = 0;
    size_t n = len / sizeof(struct kinfo_proc);
    const char *target = name.UTF8String;
    size_t tlen = strlen(target);
    for (size_t i = 0; i < n; i++) {
        if (tlen > 0 && strncmp(procs[i].kp_proc.p_comm, target, tlen) == 0) {
            result = procs[i].kp_proc.p_pid;
            break;
        }
    }
    free(procs);
    return result;
}

+ (uint64_t)findProcByPid:(int)pid {
    if (!g_ready) return 0;
    uint64_t pidOff    = cfm_kfd_dyn(g_kfd, KD_PROC_PID);
    uint64_t lePrevOff = cfm_kfd_dyn(g_kfd, KD_PROC_LE_PREV);

    // libkfd 的 idiom：kernel_proc 是 allproc 链表最后一个，
    // le_prev 的值即前一个 proc 基址（p_list.le_next 在偏移 0），往回走覆盖全表
    uint64_t proc = cfm_kfd_info_kaddr(g_kfd, KI_KERNEL_PROC);
    int guard = 0;
    while (proc != 0 && guard++ < 4096) {
        int32_t p = [self kread32:proc + pidOff];
        if (p == pid) return proc;
        uint64_t prev = [self kread64:proc + lePrevOff];
        if (prev < KPTR_MIN) break;                 // 非内核指针 = 走到头
        if (prev == proc) break;                    // 自环防御
        proc = prev;
    }
    return 0;
}

+ (uint64_t)gameBaseForPid:(int)pid {
    if (!g_ready) return 0;
    uint64_t proc = [self findProcByPid:pid];
    if (proc == 0 || g_offProcTask == 0) return 0;

    uint64_t task = [self kread64:proc + g_offProcTask];
    if (task == 0) return 0;

    uint64_t map = [self kread64:task + cfm_kfd_dyn(g_kfd, KD_TASK_MAP)];
    if (map == 0) return 0;

    // 缓存游戏 ttbr（后面每 tick 翻译都用它，避免重复走 proc 链）
    uint64_t pmap = [self kread64:map + g_offMapPmap];
    if (pmap != 0 && g_offPmapTTBR != 0) {
        g_gameTTBR = [self kread64:pmap + g_offPmapTTBR] & PA_MASK;
    }

    // min_offset（hdr.links.start）= 进程最低映射 = 主可执行文件基址
    return [self kread64:map + cfm_vmmap_min_offset()];
}

#pragma mark - 游戏进程内存读写（页表翻译）

+ (void)setCachedGamePid:(int)pid {
    if (pid != g_cfm_game_pid) {
        g_cfm_game_pid = pid;
        g_gameTTBR = 0;   // 进程换了，ttbr 作废
    }
}

+ (int)cachedGamePid {
    return g_cfm_game_pid;
}

+ (uint64_t)gameRead64:(uint64_t)gameVA {
    if (!g_ready || gameVA == 0) return 0;
    if (g_gameTTBR == 0) {
        [self gameBaseForPid:g_cfm_game_pid];   // 顺路重建 ttbr 缓存
    }
    if (g_gameTTBR == 0) return 0;

    uint64_t pa = [self translateVA:gameVA ttbr:g_gameTTBR];
    if (pa == 0) return 0;
    return [self kread64:pa];
}

+ (BOOL)gameWrite32:(uint64_t)gameVA value:(uint32_t)value {
    if (!g_ready || gameVA == 0) return NO;
    if (g_gameTTBR == 0) {
        [self gameBaseForPid:g_cfm_game_pid];
    }
    if (g_gameTTBR == 0) return NO;

    uint64_t pa = [self translateVA:gameVA ttbr:g_gameTTBR];
    if (pa == 0) return NO;
    [self kwrite32:pa value:value];
    return YES;
}

+ (BOOL)gameWrite64:(uint64_t)gameVA value:(uint64_t)value {
    if (!g_ready || gameVA == 0) return NO;
    if (g_gameTTBR == 0) {
        [self gameBaseForPid:g_cfm_game_pid];
    }
    if (g_gameTTBR == 0) return NO;

    uint64_t pa = [self translateVA:gameVA ttbr:g_gameTTBR];
    if (pa == 0) return NO;
    [self kwrite64:pa value:value];
    return YES;
}

#pragma mark - 游戏指针链读写

+ (uint64_t)gameReadChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count {
    // CE 惯例：每级先加偏移再解引用
    uint64_t cur = base;
    for (int i = 0; i < count; i++) {
        cur = cur + offsets[i];
        cur = [self gameRead64:cur];
        if (cur == 0) return 0;
    }
    return cur;
}

+ (BOOL)gameWriteChain32:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint32_t)value {
    if (count <= 0) return NO;
    uint64_t cur = base;
    // 走前 n-1 级：加偏移 -> 解引用
    for (int i = 0; i < count - 1; i++) {
        cur = cur + offsets[i];
        cur = [self gameRead64:cur];
        if (cur == 0) return NO;
    }
    // 末级不解引用：写入地址 = cur + 末级偏移
    uint64_t target = cur + offsets[count - 1];
    return [self gameWrite32:target value:value];
}

@end
