//
//  DeviceManager.h
//  CFMCheat
//
//  「注销设备」—— 清除授权绑定/激活状态，回到未授权
//  对应靶场：验证通过标志清零 + 删除本地授权 plist
//

#import <Foundation/Foundation.h>

@interface DeviceManager : NSObject

// 注销当前设备：清授权标志 + 删授权偏好文件
+ (BOOL)unregister;

// 查询当前授权状态
+ (NSDictionary *)authorizationStatus;

// 授权偏好 plist 路径（可配置）
+ (NSString *)licensePlistPath;

@end
