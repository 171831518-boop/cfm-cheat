//
//  DeviceManager.m
//  CFMCheat
//
//  注销设备实现
//
//  等价靶场「注销设备」：清授权绑定，回到未授权初始状态。
//  对本 App 的实际动作：
//   1. 停掉读写循环（CheatLoop）
//   2. 释放内核读写（KernelRW teardown）
//   3. 清授权标志 + 删授权 plist + 清 NSUserDefaults
//

#import "DeviceManager.h"
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "CheatLoop.h"
#import "KernelRW.h"

@implementation DeviceManager

// 授权偏好文件 —— 用自己的 bundle id 对应的偏好
+ (NSString *)licensePlistPath {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.cfm.cheat";
    NSString *path = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID];
    return path;
}

+ (NSDictionary *)authorizationStatus {
    NSString *path = [self licensePlistPath];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];

    NSMutableDictionary *status = [NSMutableDictionary dictionary];
    status[@"licenseFileExists"] = @([[NSFileManager defaultManager] fileExistsAtPath:path]);
    status[@"licenseData"] = plist ?: @{};
    status[@"unregistered"] = @(plist == nil);
    status[@"krwReady"] = @([KernelRW isReady]);
    return status;
}

+ (BOOL)unregister {
    // 1. 停读写循环
    [[CheatLoop shared] stop];

    // 2. 释放内核读写（kfd teardown，下次点「获取 root」重新打 exploit）
    [KernelRW teardown];

    // 3. 删除授权 plist
    NSString *path = [self licensePlistPath];
    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL deleted = YES;
    if ([fm fileExistsAtPath:path]) {
        NSError *err = nil;
        deleted = [fm removeItemAtPath:path error:&err];
        if (!deleted) {
            NSLog(@"[CFMCheat] 删除授权文件失败: %@", err);
        }
    }

    // 4. 同步偏好（让删除生效）
    CFPreferencesAppSynchronize((__bridge CFStringRef)[[NSBundle mainBundle] bundleIdentifier]);

    // 5. 清 NSUserDefaults 里的授权相关键
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:@"验证通过"];
    [ud removeObjectForKey:@"授权状态"];
    [ud removeObjectForKey:@"license"];
    [ud removeObjectForKey:@"activation"];
    [ud synchronize];

    NSLog(@"[CFMCheat] 注销设备完成 deleted=%d", deleted);
    return deleted;
}

@end
