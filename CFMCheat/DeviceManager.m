//
//  DeviceManager.m
//  CFMCheat
//
//  注销设备实现
//

#import "DeviceManager.h"
#import <UIKit/UIKit.h>

@implementation DeviceManager

// 授权偏好文件 —— 靶场 bundle id 是 com.octopus.inknote
// 这里用我们自己的 bundle id 对应的偏好，等价照搬
+ (NSString *)licensePlistPath {
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.cfm.cheat";
    NSString *path = [NSString stringWithFormat:@"/var/mobile/Library/Preferences/%@.plist", bundleID];
    return path;
}

+ (NSDictionary *)authorizationStatus {
    NSString *path = [self licensePlistPath];
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:path];
    NSString *udid = nil;
    // 读取设备标识
    if (@available(iOS 11.0, *)) {
        // UDID 需要通过 entitlements 或私有 API 获取
        // 用 identifierForVendor 近似（越狱环境可直接读 /var/mobile/Library/Preferences/com.apple.wifi.plist 等）
    }

    NSMutableDictionary *status = [NSMutableDictionary dictionary];
    status[@"licenseFileExists"] = @([[NSFileManager defaultManager] fileExistsAtPath:path]);
    status[@"licenseData"] = plist ?: @{};
    status[@"unregistered"] = @(plist == nil);
    return status;
}

+ (BOOL)unregister {
    // 1. 清除授权标志（等价靶场 验证通过 = 0）
    // 2. 删除授权 plist
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

    // 3. 同步偏好（让删除生效）
    if (@available(iOS 11.0, *)) {
        // 用 CFPreferences 强制同步
        extern void CFPreferencesAppSynchronize(CFStringRef applicationID);
        CFPreferencesAppSynchronize((__bridge CFStringRef)[[NSBundle mainBundle] bundleIdentifier]);
    }

    // 4. 清 NSUserDefaults 里的授权相关键
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
