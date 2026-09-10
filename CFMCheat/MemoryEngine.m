//
//  MemoryEngine.m
//  CFMCheat
//
//  内存读写引擎实现
//

#import "MemoryEngine.h"
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>

// 新 SDK (Xcode 26+) 的 mach/mach_vm.h 直接 #error，改为手动 extern 声明。
// 这些符号都在 libsystem_kernel.dylib 里，真实存在。
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task,
                                   mach_vm_address_t address,
                                   vm_offset_t data,
                                   mach_msg_type_number_t size);

// task_for_pid 在 iOS 上非公开 API，需手动声明（越狱环境有效）
extern kern_return_t task_for_pid(mach_port_t target_tport, int pid, mach_port_t *t);
// mach_vm_region 声明
extern kern_return_t mach_vm_region(vm_map_read_t target_task,
                                    mach_vm_address_t *address,
                                    mach_vm_size_t *size,
                                    vm_region_flavor_t flavor,
                                    vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt,
                                    mach_port_t *object_name);

@implementation MemoryEngine

+ (instancetype)shared {
    static MemoryEngine *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[MemoryEngine alloc] init]; });
    return inst;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _task = MACH_PORT_NULL;
        _base = 0;
        _pid = 0;
    }
    return self;
}

#pragma mark - 进程查找

// 遍历系统所有进程，按名字匹配 pid
+ (pid_t)pidForProcessName:(NSString *)name {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return 0;
    if (len == 0) return 0;

    struct kinfo_proc *procs = malloc(len);
    if (!procs) return 0;
    if (sysctl(mib, 4, procs, &len, NULL, 0) < 0) { free(procs); return 0; }

    size_t count = len / sizeof(struct kinfo_proc);
    pid_t found = 0;
    for (size_t i = 0; i < count; i++) {
        NSString *pname = [NSString stringWithUTF8String:procs[i].kp_proc.p_comm];
        if ([pname isEqualToString:name] || [pname containsString:name]) {
            found = procs[i].kp_proc.p_pid;
            break;
        }
    }
    free(procs);
    return found;
}

- (BOOL)attachToProcessNamed:(NSString *)name {
    pid_t pid = [MemoryEngine pidForProcessName:name];
    if (pid == 0) {
        NSLog(@"[CFMCheat] 未找到进程: %@", name);
        return NO;
    }
    _pid = pid;
    _procName = name;

    kern_return_t kr = task_for_pid(mach_task_self(), pid, &_task);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[CFMCheat] task_for_pid 失败: %d (pid=%d) —— 需要越狱 + 签名 entitlements", kr, pid);
        _task = MACH_PORT_NULL;
        return NO;
    }

    _base = [self resolveBaseAddress];
    NSLog(@"[CFMCheat] 附加成功 pid=%d task=%u base=0x%llx", pid, _task, _base);
    return YES;
}

#pragma mark - 基址解析

- (uint64_t)resolveBaseAddress {
    if (_pid == 0 || _task == MACH_PORT_NULL) return 0;

    // 读目标进程的 image 列表头（模仿 dyld_all_image_infos）
    // 更简单可靠：遍历目标进程内存，找第一个可执行段
    // 这里用 mach_vm_region 遍历找主模块 __TEXT
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    while (1) {
        kern_return_t kr = mach_vm_region(_task, &addr, &size,
                                          VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info,
                                          &count, &object_name);
        if (kr != KERN_SUCCESS) break;

        // 主模块 __TEXT：可执行 + 可读，且地址在 0x100000000 附近（iOS 主二进制固定加载地址）
        if ((info.protection & VM_PROT_EXECUTE) && (info.protection & VM_PROT_READ)) {
            if (addr >= 0x100000000ULL && addr < 0x200000000ULL) {
                return addr;
            }
        }
        addr += size;
        if (addr > 0x200000000ULL) break;
    }
    return 0;
}

#pragma mark - 读写原语

- (BOOL)readBytes:(void *)buf length:(size_t)len at:(uint64_t)addr {
    if (_task == MACH_PORT_NULL) return NO;
    mach_vm_size_t outsize = 0;
    kern_return_t kr = mach_vm_read_overwrite(_task, addr, len,
                                              (mach_vm_address_t)buf, &outsize);
    return kr == KERN_SUCCESS && outsize == len;
}

- (uint32_t)read32:(uint64_t)addr {
    uint32_t val = 0;
    [self readBytes:&val length:4 at:addr];
    return val;
}

- (uint64_t)read64:(uint64_t)addr {
    uint64_t val = 0;
    [self readBytes:&val length:8 at:addr];
    return val;
}

- (BOOL)writeBytes:(const void *)buf length:(size_t)len at:(uint64_t)addr {
    if (_task == MACH_PORT_NULL) return NO;
    kern_return_t kr = mach_vm_write(_task, addr, (vm_offset_t)buf, (mach_msg_type_number_t)len);
    return kr == KERN_SUCCESS;
}

- (BOOL)write32:(uint64_t)addr value:(uint32_t)val {
    return [self writeBytes:&val length:4 at:addr];
}

- (BOOL)write64:(uint64_t)addr value:(uint64_t)val {
    return [self writeBytes:&val length:8 at:addr];
}

#pragma mark - 指针链

// 链语义（修正）：每一步 cur = read64(cur) + off，即先解引用再加偏移。
// 老板链：cf + 0xC000060 + 0xA0 + ...  =  [[[cf] + 0xC000060] + 0xA0] + ...
- (uint64_t)followChain:(NSArray<NSNumber *> *)offsets {
    uint64_t cur = _base;
    for (NSNumber *n in offsets) {
        uint64_t off = [n unsignedLongLongValue];
        cur = [self read64:cur];      // 先解引用
        if (cur == 0) return 0;       // 链断了
        cur += off;                   // 再加偏移
    }
    return cur;
}

- (BOOL)writeChain:(NSArray<NSNumber *> *)offsets value:(uint64_t)value {
    if (offsets.count == 0) return NO;

    // 走链到倒数第二级，得到末级「解引用后的指针」
    uint64_t cur = _base;
    for (NSUInteger i = 0; i < offsets.count - 1; i++) {
        uint64_t off = [offsets[i] unsignedLongLongValue];
        cur = [self read64:cur];      // 解引用
        if (cur == 0) return NO;
        cur += off;
    }
    // 末级：解引用 + 末级偏移 = 最终写入地址
    uint64_t lastOff = [offsets[offsets.count - 1] unsignedLongLongValue];
    uint64_t finalPtr = [self read64:cur];
    if (finalPtr == 0) return NO;
    uint64_t target = finalPtr + lastOff;

    // 按值大小选择 4 字节或 8 字节写
    if (value <= 0xFFFFFFFFULL) {
        return [self write32:target value:(uint32_t)value];
    } else {
        return [self write64:target value:value];
    }
}

// C 数组版：链 [[[base]+off0]+off1]+...+off[n-1]，末级写 value
- (BOOL)writeChain64:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count value:(uint64_t)value {
    if (count <= 0) return NO;
    uint64_t cur = base;
    // 走链到倒数第二级（解引用 + 加偏移）
    for (int i = 0; i < count - 1; i++) {
        cur = [self read64:cur];
        if (cur == 0) return NO;
        cur += offsets[i];
    }
    // 末级：解引用 + 末级偏移 = 写入地址
    uint64_t finalPtr = [self read64:cur];
    if (finalPtr == 0) return NO;
    uint64_t target = finalPtr + offsets[count - 1];
    return [self write64:target value:value];
}

- (uint64_t)readChain64:(uint64_t)base offsets:(const uint64_t *)offsets count:(int)count {
    uint64_t cur = base;
    for (int i = 0; i < count; i++) {
        cur = [self read64:cur];
        if (cur == 0) return 0;
        cur += offsets[i];
    }
    return cur;
}

@end
