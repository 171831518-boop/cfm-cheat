//
//  ViewController.m
//  CFMCheat
//
//  主界面：获取root / 开始读写 / 注销设备 / 红透 / 吸附
//
//  v2：「获取 root」在后台线程打 kfd exploit（几秒到几十秒），主线程只转圈，
//  不再冻 UI；不支持的系统版本直接报原因，不跑 exploit。
//

#import "ViewController.h"
#import "RootHelper.h"
#import "MemoryEngine.h"
#import "CheatLoop.h"
#import "DeviceManager.h"
#import "KernelRW.h"

@interface ViewController ()

@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIButton *rootButton;
@property (nonatomic, strong) UISwitch *hongtouSwitch;
@property (nonatomic, strong) UISwitch *xifuSwitch;
@property (nonatomic, assign) BOOL acquiring;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"CFM 外挂";

    [self buildUI];

    // 启动即做支持性预检，把结果亮出来
    NSString *err = [KernelRW supportError];
    if (err) {
        self.statusLabel.text = [NSString stringWithFormat:@"⚠️ 免越狱提权预检未通过：\n%@", err];
        self.statusLabel.textColor = [UIColor systemOrangeColor];
    } else {
        self.statusLabel.text = @"✅ 当前内核版本在 kfd 支持表内，可点「获取 root」";
        self.statusLabel.textColor = [UIColor systemGreenColor];
    }
}

- (void)buildUI {
    CGFloat y = 120;
    CGFloat w = self.view.bounds.size.width - 40;
    CGFloat h = 56;

    // 状态标签
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 70, w, 60)];
    self.statusLabel.font = [UIFont systemFontOfSize:12];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.textColor = [UIColor grayColor];
    self.statusLabel.text = @"未连接";
    [self.view addSubview:self.statusLabel];

    // 获取 root 按钮
    y = 140;
    self.rootButton = [self addButton:@"获取 root" atY:y action:@selector(onGainRoot:)];
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

- (UIButton *)addButton:(NSString *)title atY:(CGFloat)y action:(SEL)sel {
    CGFloat w = self.view.bounds.size.width - 40;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(20, y, w, 56);
    [btn setTitle:title forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor systemBlueColor];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.layer.cornerRadius = 8;
    [btn addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:btn];
    return btn;
}

- (void)addSwitch:(NSString *)title atY:(CGFloat)y switchRef:(UISwitch *__strong *)ref {
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
    if (self.acquiring) return;

    // 预检：不支持直接说原因，不跑 exploit
    NSString *err = [KernelRW supportError];
    if (err) {
        self.statusLabel.text = [NSString stringWithFormat:@"⚠️ 预检未通过：\n%@", err];
        self.statusLabel.textColor = [UIColor systemOrangeColor];
        return;
    }

    // KRW 已就绪
    if ([KernelRW isReady]) {
        self.statusLabel.text = @"root 已获取（kfd 内核读写就绪）";
        return;
    }

    // 后台跑 exploit，主线程转圈
    self.acquiring = YES;
    self.rootButton.enabled = NO;
    [self.rootButton setTitle:@"提权中…（几秒到几十秒）" forState:UIControlStateDisabled];
    self.statusLabel.textColor = [UIColor grayColor];
    self.statusLabel.text = @"正在打 kfd 内核漏洞…";

    [[NSUserDefaults standardUserDefaults] synchronize];

    [KernelRW acquireWithProgress:^(NSString *msg) {
        self.statusLabel.text = msg;
    } completion:^(BOOL ok, NSString *msg) {
        self.acquiring = NO;
        self.rootButton.enabled = YES;
        [self.rootButton setTitle:@"获取 root" forState:UIControlStateNormal];
        self.statusLabel.text = msg;
        self.statusLabel.textColor = ok ? [UIColor systemGreenColor] : [UIColor systemRedColor];

        if (ok) {
            [self tryStartLoopIfSwitchesOn];
        } else if (![KernelRW isSupported]) {
            // kfd 失败且回退越狱路线
            [self fallbackJailbreakRoot];
        }
    }];
}

- (void)fallbackJailbreakRoot {
    BOOL jb = [RootHelper isJailbroken];
    if (!jb) return;
    BOOL root = [RootHelper isRoot];
    BOOL gained = [RootHelper gainRoot];
    if (root || gained) {
        self.statusLabel.text = [NSString stringWithFormat:@"root 已获取 (euid=%d)", geteuid()];
        self.statusLabel.textColor = [UIColor systemGreenColor];
    } else {
        self.statusLabel.text = @"已越狱但提权失败，检查签名 entitlements";
        self.statusLabel.textColor = [UIColor systemRedColor];
    }
}

// 开关本来就开着时，提权成功直接起循环
- (void)tryStartLoopIfSwitchesOn {
    if (self.hongtouSwitch.isOn || self.xifuSwitch.isOn) {
        [self startLoop];
    }
}

- (void)startLoop {
    CheatLoop *loop = [CheatLoop shared];
    loop.hongtouEnabled = self.hongtouSwitch.isOn;
    loop.xifuEnabled = self.xifuSwitch.isOn;
    [loop start];
}

- (void)onStartReadWrite:(id)sender {
    // KRW 路线（免越狱）
    if ([KernelRW isReady]) {
        [self startLoop];
        self.statusLabel.text = @"读写循环已启动（KRW 内核路线）";
        self.statusLabel.textColor = [UIColor systemGreenColor];
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
        self.statusLabel.textColor = [UIColor systemRedColor];
        return;
    }

    [self startLoop];
    self.statusLabel.text = [NSString stringWithFormat:
        @"已连接 %@ pid=%d base=0x%llx\n读写循环已启动", procName, eng.pid, eng.base];
    self.statusLabel.textColor = [UIColor systemGreenColor];
}

- (void)onUnregister:(id)sender {
    BOOL ok = [DeviceManager unregister];
    self.statusLabel.text = ok
        ? @"已注销：内核读写已释放、循环已停止、授权状态已清除"
        : @"注销失败";
    self.statusLabel.textColor = ok ? [UIColor systemGreenColor] : [UIColor systemRedColor];
}

- (void)onSwitchChanged:(UISwitch *)sw {
    if (sw == self.hongtouSwitch) {
        [CheatLoop shared].hongtouEnabled = sw.isOn;
        NSLog(@"[CFMCheat] 红透 = %d", sw.isOn);
    } else if (sw == self.xifuSwitch) {
        [CheatLoop shared].xifuEnabled = sw.isOn;
        NSLog(@"[CFMCheat] 吸附 = %d", sw.isOn);
    }
}

@end
