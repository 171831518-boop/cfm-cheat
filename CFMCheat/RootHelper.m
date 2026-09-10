//
//  RootHelper.m
//  CFMCheat
//
//  提权实现
//

#import "RootHelper.h"
#import <sys/stat.h>
#import <sys/types.h>
#import <unistd.h>
#import <spawn.h>
#import <dlfcn.h>

extern char **environ;

@implementation RootHelper

#pragma mark - 越狱/root 检测

+ (BOOL)isJailbroken {
    // 常见越狱文件/路径检测
    NSArray *paths = @[
        @"/Applications/Cydia.app",
        @"/usr/sbin/sshd",
        @"/bin/bash",
        @"/usr/bin/ssh",
        @"/etc/apt",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/var/lib/cydia",
        @"/var/tmp/cydia.log",
        @"/var/log/syslog",
        @"/private/var/stash",
        @"/.installed_dopamine",
        @"/.bootstrapped_electra",
        @"/.procursus_strapped",
        @"/var/jb",
    ];
    for (NSString *p in paths) {
        if (access(p.UTF8String, F_OK) == 0) return YES;
    }

    // 检测是否可写入根文件系统（越狱核心特征）
    const char *test = "/.cfm_cheat_rw_test";
    FILE *f = fopen(test, "w");
    if (f) {
        fclose(f);
        unlink(test);
        return YES;
    }
    return NO;
}

+ (BOOL)isRoot {
    return geteuid() == 0 || getuid() == 0;
}

#pragma mark - 提权

+ (BOOL)gainRoot {
    if ([self isRoot]) return YES;
    // setuid(0) 只有在已越狱、且进程有 root 提权能力时才能成功
    // 越狱环境通常已带 root，或通过 platformize 后 setuid
    int r = setuid(0);
    if (r == 0) return YES;

    // 尝试 setgid 0
    setgid(0);
    r = setuid(0);
    return r == 0;
}

#pragma mark - root 命令执行

+ (NSString *)runCommandAsRoot:(NSString *)command {
    // 用 posix_spawn 跑 /bin/sh -c，需要 root 才可能对 root 文件系统生效
    // 越狱环境用 bootstrap 的 shell
    NSArray *shells = @[@"/bin/sh", @"/usr/bin/sh", @"/bin/bash", @"/usr/bin/bash", @"/var/jb/bin/sh", @"/var/jb/usr/bin/sh"];
    for (NSString *shell in shells) {
        if (access(shell.UTF8String, X_OK) != 0) continue;

        int outPipe[2];
        pipe(outPipe);

        const char *argv[] = { shell.UTF8String, "-c", command.UTF8String, NULL };
        pid_t pid;
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, outPipe[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, outPipe[0]);
        posix_spawn_file_actions_addclose(&actions, outPipe[1]);

        int status = posix_spawn(&pid, shell.UTF8String, &actions, NULL, (char *const *)argv, environ);
        posix_spawn_file_actions_destroy(&actions);
        close(outPipe[1]);

        if (status != 0) {
            close(outPipe[0]);
            continue;
        }

        NSMutableData *out = [NSMutableData data];
        char buf[4096];
        ssize_t n;
        while ((n = read(outPipe[0], buf, sizeof(buf))) > 0) {
            [out appendBytes:buf length:n];
        }
        close(outPipe[0]);
        waitpid(pid, NULL, 0);

        return [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
    }
    return nil;
}

#pragma mark - root 文件系统信息

+ (NSDictionary *)rootFSInfo {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[@"euid"] = @(geteuid());
    info[@"uid"] = @(getuid());
    info[@"jailbroken"] = @([self isJailbroken]);
    info[@"isRoot"] = @([self isRoot]);

    // 探测关键越狱组件
    if (access("/var/jb", F_OK) == 0) info[@"bootstrap"] = @"/var/jb (Procursus/rootless)";
    else if (access("/usr/lib/libjailbreak.dylib", F_OK) == 0) info[@"bootstrap"] = @"/usr/lib (rootful)";

    // 列出根目录（验证 root 可读）
    NSArray *rootEntries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/" error:nil];
    if (rootEntries) info[@"rootListing"] = [rootEntries componentsJoinedByString:@", "];

    return info;
}

@end
