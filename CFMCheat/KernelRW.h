//
//  KernelRW.h
//  CFMCheat
//
//  内核读写模块（kfd 提权链封装）
//  等价靶场「获取 root」：打 kfd 拿 KRW，通过内核 proc/task/pmap 读写游戏进程内存
//
//  v2 关键修正：
//   1. acquire 全部在后台线程执行（exploit 要跑几秒到几十秒，主线程跑必卡死）
//   2. libkfd 的 assert 失败不再 sleep(30)+exit(1) 杀 App（见 kfd_shim.c）
//   3. 所有内核结构偏移从 libkfd 运行时数据取（info.kaddr/dynamic_info/perf），
//      不再使用占位符
//   4. 游戏进程内存读写走 pmap 页表翻译 VA->PA->内核VA（直接 kwrite 游戏用户态
//      地址是无效的——用户态地址只在目标进程地址空间有效）
//

#import <Foundation/Foundation.h>
#import <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// libkfd 公开 API
//   u64 kopen(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method);
//   void kread(u64 kfd, u64 kaddr, void* uaddr, u64 size);
//   void kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size);
//   void kclose(u64 kfd);

typedef enum {
    puaf_physpuppet = 0,   // CVE-2023-23536, iOS 15.0 ~ 16.3.x
    puaf_smith      = 1,   // CVE-2023-32434, iOS 16.4 ~ 16.5
    puaf_landa      = 2,   // CVE-2023-41974, iOS 16.6 ~ 16.6.1
} puaf_method_t;

typedef enum {
    kread_kqueue_workloop_ctl = 0,
    kread_sem_open            = 1,
} kread_method_t;

typedef enum {
    kwrite_dup      = 0,
    kwrite_sem_open = 1,
} kwrite_method_t;

@interface KernelRW : NSObject

// —— 支持性预检（不再盲目跑 exploit）——
// 返回 nil = 当前内核版本在 libkfd 的 kern_versions 表内，可以试；
// 返回非 nil = 不支持的原因描述（直接展示给用户，不跑 exploit）
+ (nullable NSString *)supportError;
+ (BOOL)isSupported;

// —— 提权（等价靶场「获取 root」）——
// 后台线程执行 exploit，progress/completion 回主线程。耗时几秒到几十秒。
+ (void)acquireWithProgress:(void(^)(NSString *msg))progress
                 completion:(void(^)(BOOL ok, NSString *msg))completion;
+ (void)teardown;                    // 关闭 kfd，释放
+ (BOOL)isReady;                     // KRW 是否已建立

// —— 内核读写原语（等价靶场 remote_read64 / remote_write_int）——
+ (uint64_t)kread64:(uint64_t)kaddr;
+ (uint32_t)kread32:(uint64_t)kaddr;
+ (void)kwrite64:(uint64_t)kaddr value:(uint64_t)value;
+ (void)kwrite32:(uint64_t)kaddr value:(uint32_t)value;
+ (void)kreadBuf:(uint64_t)kaddr buf:(void *)buf size:(uint64_t)size;

// —— 内核定位游戏进程（等价靶场 xpf_find_allproc + _cfm_taskAddr）——
+ (int)findGamePidByName:(NSString *)name;      // sysctl KERN_PROC_ALL 查 pid
+ (uint64_t)findProcByPid:(int)pid;             // 内核 proc 地址
+ (uint64_t)gameBaseForPid:(int)pid;            // 游戏主模块基址（等价 cf）

// 游戏 pid 缓存（定位基址后设置，页表翻译要用它找 ttbr）
+ (void)setCachedGamePid:(int)pid;
+ (int)cachedGamePid;

// —— 游戏进程内存读写（pmap 页表翻译 VA->PA->内核VA）——
+ (uint64_t)gameRead64:(uint64_t)gameVA;
+ (BOOL)gameWrite32:(uint64_t)gameVA value:(uint32_t)value;
+ (BOOL)gameWrite64:(uint64_t)gameVA value:(uint64_t)value;

// —— 游戏指针链读写（等价靶场走链写值）——
// 链语义（CE 惯例）：addr = base+off0 -> *(addr)+off1 -> *(addr)+off2 -> ...
// 末级不解引用：写入地址 = 倒数第二级解引用结果 + 最后一级偏移
+ (uint64_t)gameReadChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count;
+ (BOOL)gameWriteChain32:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint32_t)value;

@end

NS_ASSUME_NONNULL_END
