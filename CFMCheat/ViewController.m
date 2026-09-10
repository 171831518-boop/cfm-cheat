//
//  ViewController.m
//  CFMCheat
//
//  主界面：获取root / 开始读写 / 注销设备 / 红透 / 吸附
//

#import "ViewController.h"
#import "RootHelper.h"
#import "MemoryEngine.h"
#import "CheatLoop.h"
#import "DeviceManager.h"
#import "KernelRW.h"

@interface ViewController ()

@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UISwitch *hongtouSwitch;
@property (nonatomic, strong) UISwitch *xifuSwitch;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"CFM 外挂";

    [self buildUI];
}

- (void)buildUI {
    CGFloat y = 120;
    CGFloat w = self.view.bounds.size.width - 40;
    CGFloat h = 56;

    // 状态标签
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 80, w, 40)];
    self.statusLabel.font = [UIFont systemFontOfSize:13];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.textColor = [UIColor grayColor];
    self.statusLabel.text = @"未连接";
    [self.view addSubview:self.statusLabel];

    // 获取 root 按钮
    y = 130;
    [self addButton:@"获取 root" atY:y action:@selector(onGainRoot:)];
    y += h + 12;

    // 开始读写 按钮
    [self addButton:@"开始读写" atY:y action:@selector(onStartReadWrite:)];
    y += h + 12;

    // 注销设备 按钮
    [self addButton:@"注销设备" atY:y action:@selector(onUnregister:)];
    y += h + 20;

    // 红透开关
    [self addSwitch:@"红透" atY:y switchRef:&_hongtouSwitch];
    y += h + 8;

    // 吸附开关
    [self addSwitch:@"吸附" atY:y switchRef:&_xifuSwitch];
}

- (void)addButton:(NSString *)title atY:(CGFloat)y action:(SEL)sel {
    CGFloat w = self.view.bounds.size.width - 40;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(20, y, w, 56);
    [btn setTitle:title forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor systemBlueColor];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.layer.cornerRadius = 8;
    [btn addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
}

- (void)addSwitch:(NSString *)title atY:(CGFloat)y switchRef:(UISwitch * __unsafe_unretained *)ref {
    CGFloat w = self.view.bounds.size.width - 40;
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(20, y, 120, 40)];
    lbl.text = title;
    [self.view addSubview:lbl];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(w - 20 - 51, y, 51, 31)];
    [sw addTarget:self action:@selector(onSwitchChanged:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:sw];
    *ref = sw;
}

#pragma mark - 功能动作

- (void)onGainRoot:(id)sender {
    // 等价靶场「获取 root」：优先打 kfd 拿内核读写（免越狱），回退越狱 setuid
    BOOL supported = [KernelRW isSupported];
    BOOL acquired = [KernelRW acquire];

    if (acquired) {
        self.statusLabel.text = @"root 已获取（kfd 内核读写就绪）";
        NSLog(@"[CFMCheat] kfd KRW acquired");
        return;
    }

    // 回退：越狱 setuid 路线
    BOOL jb = [RootHelper isJailbroken];
    BOOL root = [RootHelper isRoot];
    BOOL gained = [RootHelper gainRoot];

    if (root || gained) {
        self.statusLabel.text = [NSString stringWithFormat:@"root 已获取 (euid=%d)", geteuid()];
    } else if (jb) {
        self.statusLabel.text = @"已越狱但提权失败，检查签名 entitlements";
    } else {
        self.statusLabel.text = supported
            ? @"kfd 提权失败（可重试）"
            : @"当前 iOS 版本不支持免越狱提权";
    }
}

- (void)onStartReadWrite:(id)sender {
    // 优先 KernelRW 路线（免越狱），回退 mach 路线（越狱）
    if ([KernelRW isReady]) {
        // CheatLoop 的 tick 会自动通过 KernelRW 定位游戏基址，这里只启动循环
        [CheatLoop shared].hongtouEnabled = self.hongtouSwitch.isOn;
        [CheatLoop shared].xifuEnabled = self.xifuSwitch.isOn;
        [[CheatLoop shared] start];
        self.statusLabel.text = @"读写循环已启动（KRW 内核路线）";
        return;
    }

    // 回退 mach 路线：附加游戏进程
    MemoryEngine *eng = [MemoryEngine shared];
    NSString *procName = @"穿越火线";
    BOOL ok = [eng attachToProcessNamed:procName];
    if (!ok) {
        NSArray *alts = @[@"cfm", @"CrossFire", @"穿越火线", @"CF", @"com.tencent.tmgp.cf"];
        for (NSString *n in alts) {
            if ([eng attachToProcessNamed:n]) { ok = YES; procName = n; break; }
        }
    }
    if (!ok) {
        self.statusLabel.text = @"附加失败：游戏未运行或无权访问（先点「获取 root」）";
        return;
    }

    self.statusLabel.text = [NSString stringWithFormat:@"已连接 %@ pid=%d base=0x%llx", procName, eng.pid, eng.base];

    CheatLoop *loop = [CheatLoop shared];
    loop.hongtouEnabled = self.hongtouSwitch.isOn;
    loop.xifuEnabled = self.xifuSwitch.isOn;
    [loop start];

    self.statusLabel.text = [self.statusLabel.text stringByAppendingString:@"\n读写循环已启动"];
}

- (void)onUnregister:(id)sender {
    BOOL ok = [DeviceManager unregister];
    self.statusLabel.text = ok ? @"已注销设备" : @"注销失败";
}

- (void)onSwitchChanged:(UISwitch *)sw {
    // 实时同步到循环
    if (sw == self.hongtouSwitch) {
        [CheatLoop shared].hongtouEnabled = sw.isOn;
        NSLog(@"[CFMCheat] 红透 = %d", sw.isOn);
    } else if (sw == self.xifuSwitch) {
        [CheatLoop shared].xifuEnabled = sw.isOn;
        NSLog(@"[CFMCheat] 吸附 = %d", sw.isOn);
    }
}

@end
