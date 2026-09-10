//
//  KernelRW.h
//  CFMCheat
//
//  内核读写模块（kfd 提权链封装）
//  等价靶场「获取 root」：打 kfd 拿 KRW，通过内核 proc/task 直接读写游戏进程内存
//

#import <Foundation/Foundation.h>
#import <stdint.h>

NS_ASSUME_NONNULL_BEGIN

// libkfd 公开 API（与公开 PoC 对齐）
//   u64 kopen(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method);
//   void kread(u64 kfd, u64 kaddr, void* uaddr, u64 size);
//   void kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size);
//   void kclose(u64 kfd);

typedef enum {
    puaf_physpuppet = 0,   // CVE-2023-23536, fixed iOS 16.4
    puaf_smith      = 1,   // CVE-2023-32434, fixed iOS 16.5.1
    puaf_landa      = 2,   // CVE-2023-41974, fixed iOS 17.0
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

// —— 提权（等价靶场「获取 root」）——
+ (BOOL)isSupported;                 // 检测当前 iOS 是否有对应偏移表
+ (BOOL)acquire;                     // 打 kfd 拿 KRW，成功返回 YES
+ (void)teardown;                    // 关闭 kfd，释放（不叫 release，避免 ARC 语义冲突）
+ (BOOL)isReady;                     // KRW 是否已建立

// —— 内核读写原语（等价靶场 remote_read64 / remote_write_int）——
+ (uint64_t)kread64:(uint64_t)kaddr;
+ (uint32_t)kread32:(uint64_t)kaddr;
+ (void)kwrite64:(uint64_t)kaddr value:(uint64_t)value;
+ (void)kwrite32:(uint64_t)kaddr value:(uint32_t)value;
+ (void)kreadBuf:(uint64_t)kaddr buf:(void *)buf size:(uint64_t)size;
+ (void)kwriteBuf:(uint64_t)kaddr buf:(const void *)buf size:(uint64_t)size;

// —— 内核定位游戏进程（等价靶场 xpf_find_allproc + _cfm_taskAddr）——
+ (uint64_t)kernelBase;              // 内核基址（kslide 修正后）
+ (uint64_t)findProcByName:(NSString *)name;   // 按进程名定位 proc 地址
+ (uint64_t)findProcByPid:(int)pid;            // 按 pid 定位 proc
+ (uint64_t)procTask:(uint64_t)proc;           // proc -> task
+ (uint64_t)taskVmMap:(uint64_t)task;          // task -> vm_map
+ (uint64_t)gameBase:(NSString *)procName;     // 游戏模块基址（等价 cf/_cfm_taskAddr）

// —— 指针链读写（等价靶场走链写值）——
// 链：base + off0 -> +off1 -> +off2 -> ... 末级写入 value
+ (uint64_t)readChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count;
+ (BOOL)writeChain:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint64_t)value;

@end

NS_ASSUME_NONNULL_END
