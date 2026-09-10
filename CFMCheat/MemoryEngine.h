//
//  MemoryEngine.h
//  CFMCheat
//
//  内存读写引擎 —— 通过 Mach VM API 读写游戏进程内存
//  核心：task_for_pid 拿 task port，mach_vm_read/write 读写，走指针链
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>

@interface MemoryEngine : NSObject

// 目标进程
@property (nonatomic, assign) mach_port_t task;      // 游戏进程 task port
@property (nonatomic, assign) uint64_t base;          // 游戏主模块基址（cf）
@property (nonatomic, assign) pid_t pid;
@property (nonatomic, copy)   NSString *procName;     // 命中的进程名

// 单例
+ (instancetype)shared;

// 附加到目标进程（按进程名查找 pid）
- (BOOL)attachToProcessNamed:(NSString *)name;

// 获取进程主模块基址（__TEXT 段 vmaddr）
- (uint64_t)resolveBaseAddress;

// 读内存
- (BOOL)readBytes:(void *)buf length:(size_t)len at:(uint64_t)addr;
- (uint32_t)read32:(uint64_t)addr;
- (uint64_t)read64:(uint64_t)addr;

// 写内存
- (BOOL)writeBytes:(const void *)buf length:(size_t)len at:(uint64_t)addr;
- (BOOL)write32:(uint64_t)addr value:(uint32_t)val;
- (BOOL)write64:(uint64_t)addr value:(uint64_t)val;

// 走指针链读：[[[base]+offsets[0]]+offsets[1]]+... 最后返回末级指针值
// 语义：每一步 cur = read64(cur) + offsets[i]（先解引用再加偏移）
- (uint64_t)followChain:(NSArray<NSNumber *> *)offsets;

// 走指针链写：把链末级地址写成 value
- (BOOL)writeChain:(NSArray<NSNumber *> *)offsets value:(uint64_t)value;

// C 数组版指针链写（链：[[[base]+off0]+off1]+...+off[n-1]，末级写 value）
- (BOOL)writeChain64:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint64_t)value;
// C 数组版指针链读
- (uint64_t)readChain64:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count;

@end
