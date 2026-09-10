//
//  CheatLoop.m
//  CFMCheat
//
//  每帧功能循环实现（等价靶场 freeze_loop）
//
//  双路线：
//  1. KernelRW 路线（免越狱）：kfd 内核读写 + pmap 页表翻译写游戏进程内存
//  2. MemoryEngine 路线（越狱）：task_for_pid + mach_vm_read/write
//  优先 KernelRW（普通机可用），回退 MemoryEngine（越狱机）
//

#import "CheatLoop.h"
#import "KernelRW.h"
#import "MemoryEngine.h"

// 功能偏移链（老板给定）
// 红透：cf + 0xC000060 + 0xA0 + 0x240 + 0x108 + 0x14C  -> 写 65536
// 吸附：cf + 0xC001DF8 + 0xA0 + 0x70 + 0x1F8           -> 写 10
// 链语义（CE 惯例）：addr = base+off0；cur = *(addr)+off1；...
// 末级不解引用：写入地址 = 倒数第二级解引用结果 + 末级偏移
static const uint64_t HongtouOffsets[] = { 0xC000060, 0xA0, 0x240, 0x108, 0x14C };
static const int     HongtouCount = 5;
static const uint32_t HongtouValue = 65536;

static const uint64_t XifuOffsets[] = { 0xC001DF8, 0xA0, 0x70, 0x1F8 };
static const int     XifuCount = 4;
static const uint32_t XifuValue = 10;

// 穿越火线手游可能的进程名（p_comm 16 字节截断，中文 12 字节够用）
static NSArray<NSString *> *GameProcNames(void) {
    return @[
        @"穿越火线",
        @"CrossFire",
        @"cf",
        @"CFM",
        @"com.tencent.tmgp.cf",
    ];
}

@implementation CheatLoop {
    BOOL _running;
    dispatch_source_t _timer;
    uint64_t _gameBase;      // 游戏模块基址（cf，等价 _cfm_taskAddr）
    int      _gamePid;       // 游戏 pid
}

+ (instancetype)shared {
    static CheatLoop *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[CheatLoop alloc] init]; });
    return inst;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _running = NO;
        _hongtouEnabled = NO;
        _xifuEnabled = NO;
        _gameBase = 0;
        _gamePid = 0;
    }
    return self;
}

#pragma mark - 生命周期

- (void)start {
    if (_running) return;
    _running = YES;

    dispatch_queue_t q = dispatch_queue_create("com.cfm.cheat.loop", DISPATCH_QUEUE_SERIAL);
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    uint64_t interval = 0.1 * NSEC_PER_SEC;  // 0.1s，等价 0x186a0 us
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, 0), interval, 0);

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(_timer, ^{
        [weakSelf tick];
    });
    dispatch_resume(_timer);
    NSLog(@"[CFMCheat] 循环已启动");
}

- (void)stop {
    if (!_running) return;
    _running = NO;
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }
    NSLog(@"[CFMCheat] 循环已停止");
}

#pragma mark - 定位游戏基址

// 等价靶场 _getGame：定位游戏进程模块基址（cf）
- (uint64_t)resolveGameBase {
    if (_gameBase != 0) return _gameBase;

    // KernelRW 路线（免越狱）：sysctl 查 pid -> 内核 proc 链 -> vm_map min_offset
    if ([KernelRW isReady]) {
        for (NSString *name in GameProcNames()) {
            int pid = [KernelRW findGamePidByName:name];
            if (pid == 0) continue;
            uint64_t base = [KernelRW gameBaseForPid:pid];
            if (base != 0) {
                _gameBase = base;
                _gamePid = pid;
                [KernelRW setCachedGamePid:pid];
                NSLog(@"[CFMCheat] 游戏基址(KRW) %@ pid=%d = 0x%llx", name, pid, base);
                return base;
            }
        }
    }

    // 回退 MemoryEngine 路线（越狱）
    MemoryEngine *eng = [MemoryEngine shared];
    if (eng.task != MACH_PORT_NULL && eng.base != 0) {
        _gameBase = eng.base;
        NSLog(@"[CFMCheat] 游戏基址(mach) %@ = 0x%llx", eng.procName, eng.base);
        return _gameBase;
    }

    return 0;
}

#pragma mark - 每帧

- (void)tick {
    uint64_t base = [self resolveGameBase];
    if (base == 0) return;

    if (_hongtouEnabled) {
        if ([KernelRW isReady]) {
            [KernelRW gameWriteChain32:base offsets:HongtouOffsets count:HongtouCount value:HongtouValue];
        } else {
            MemoryEngine *eng = [MemoryEngine shared];
            [eng writeChain64:base offsets:HongtouOffsets count:HongtouCount value:HongtouValue];
        }
    }

    if (_xifuEnabled) {
        if ([KernelRW isReady]) {
            [KernelRW gameWriteChain32:base offsets:XifuOffsets count:XifuCount value:XifuValue];
        } else {
            MemoryEngine *eng = [MemoryEngine shared];
            [eng writeChain64:base offsets:XifuOffsets count:XifuCount value:XifuValue];
        }
    }
}

@end
