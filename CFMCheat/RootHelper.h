//
//  RootHelper.h
//  CFMCheat
//
//  「获取 root」—— 越狱环境提权 + root 文件系统访问
//  对应靶场内置 xpf 越狱工具链的等价能力
//

#import <Foundation/Foundation.h>

@interface RootHelper : NSObject

// 检测是否已越狱 / 是否可提权
+ (BOOL)isJailbroken;

// 检测当前是否 root（euid == 0）
+ (BOOL)isRoot;

// 提权到 root（setuid(0)，需越狱）
+ (BOOL)gainRoot;

// 以 root 执行 shell 命令，返回输出
+ (NSString *)runCommandAsRoot:(NSString *)command;

// 获取 root 文件系统关键信息（用于验证 root 可用）
+ (NSDictionary *)rootFSInfo;

@end
