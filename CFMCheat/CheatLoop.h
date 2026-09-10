//
//  CheatLoop.h
//  CFMCheat
//
//  每帧功能循环 —— 后台线程周期性写值（等价于靶场的 freeze_loop）
//

#import <Foundation/Foundation.h>

@interface CheatLoop : NSObject

+ (instancetype)shared;

// 启动循环（等价 freeze_loop 的 0.1s 周期）
- (void)start;

// 停止
- (void)stop;

// 功能开关（实时读取，开关翻转即时生效）
@property (nonatomic, assign) BOOL hongtouEnabled;  // 红透
@property (nonatomic, assign) BOOL xifuEnabled;     // 吸附

@end
