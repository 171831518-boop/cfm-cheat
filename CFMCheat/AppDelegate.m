//
//  AppDelegate.m
//  CFMCheat
//

#import "AppDelegate.h"
#import "ViewController.h"
#import <stdio.h>

// libkfd 全程用 printf 打诊断（spray/scan/KRW 每一步）。
// iOS App 的 stdout 无处可去，这里重定向到 Documents/kfd.log，
// 文件 App 里能直接取出来看。
static void redirectStdoutToLog(void) {
    NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count == 0) return;
    NSString *path = [docs[0] stringByAppendingPathComponent:@"kfd.log"];
    freopen(path.fileSystemRepresentation, "a+", stdout);
    setvbuf(stdout, NULL, _IOLBF, 0);   // 行缓冲，及时落盘
}

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    redirectStdoutToLog();

    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    ViewController *vc = [[ViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
