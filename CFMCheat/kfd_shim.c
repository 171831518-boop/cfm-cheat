//
//  kfd_shim.c
//  CFMCheat
//
//  libkfd 是 header-only 实现（kopen/kread/kwrite/kclose 全部定义在 libkfd.h 及
//  其子头文件里）。本 shim 以纯 C 编译包含它，产出 C 链接符号，供 KernelRW.m
//  的 extern 声明链接（ObjC++ 侧不能重复 include，避免符号重定义）。
//
//  关键改动 1（修"点获取 root 就卡死"）：
//    libkfd 的 assert 失败路径是 sleep(30) + exit(1)。系统版本不在 kern_versions
//    表内时 info_init 第一时间就 assert_false("unsupported osversion")，主线程
//    直接被冻 30 秒然后 App 闪退。这里用宏把 sleep/exit 重定向：
//      - sleep(30)  -> 空操作
//      - exit(1)    -> 置 panic 标志 + pthread_exit 只结束 exploit 线程
//    上层 acquire 拿到"提权失败"，App 不死。
//
//  关键改动 2：暴露一组 C 访问器（info.kaddr / dynamic_info / perf / vm_map
//  布局常量），KernelRW.m 不需要 include libkfd.h 就能拿到全部运行时数据，
//  彻底替换掉旧的占位偏移。
//

#include <pthread.h>
#include <stdint.h>

int  cfm_kfd_panic_flag = 0;

// ---- panic 拦截（签名必须与 unistd.h/stdlib.h 的 sleep/exit 声明一致，
//      因为宏展开后连系统头文件里的声明都会被改名）----
static unsigned int cfm_kfd_panic_sleep(unsigned int seconds) { (void)seconds; return 0; }

__attribute__((noreturn))
static void cfm_kfd_panic_exit(int status) {
    (void)status;
    cfm_kfd_panic_flag = 1;
    pthread_exit(NULL);
}

// 宏必须在 include libkfd.h 之前定义，assert 展开时才会命中
#define sleep cfm_kfd_panic_sleep
#define exit  cfm_kfd_panic_exit
#include "libkfd.h"
#undef sleep
#undef exit

// ======================================================================
// C 访问器 —— 给 KernelRW.m 用
// ======================================================================

// info.kaddr 里已解析好的内核地址
enum {
    CFM_KINFO_CURRENT_MAP = 0,
    CFM_KINFO_CURRENT_PMAP,
    CFM_KINFO_CURRENT_PROC,
    CFM_KINFO_CURRENT_TASK,
    CFM_KINFO_KERNEL_PROC,
    CFM_KINFO_KERNEL_TASK,
};

// dynamic_info 里当前内核版本的结构偏移
enum {
    CFM_KDYN_PROC_PID = 0,
    CFM_KDYN_PROC_LE_PREV,
    CFM_KDYN_TASK_MAP,
    CFM_KDYN_PROC_OBJ_SIZE,
    CFM_KDYN_KREAD_KQUEUE_SUPPORTED,
};

// perf 里解析好的内核全局（phys<->virt 翻译要用）
enum {
    CFM_KPERF_SLIDE = 0,
    CFM_KPERF_GVIRTBASE,
    CFM_KPERF_GPHYSBASE,
};

uint64_t cfm_kfd_info_kaddr(uint64_t kfdh, int which)
{
    struct kfd* kfd = (struct kfd*)kfdh;
    switch (which) {
        case CFM_KINFO_CURRENT_MAP:   return kfd->info.kaddr.current_map;
        case CFM_KINFO_CURRENT_PMAP:  return kfd->info.kaddr.current_pmap;
        case CFM_KINFO_CURRENT_PROC:  return kfd->info.kaddr.current_proc;
        case CFM_KINFO_CURRENT_TASK:  return kfd->info.kaddr.current_task;
        case CFM_KINFO_KERNEL_PROC:   return kfd->info.kaddr.kernel_proc;
        case CFM_KINFO_KERNEL_TASK:   return kfd->info.kaddr.kernel_task;
    }
    return 0;
}

uint64_t cfm_kfd_dyn(uint64_t kfdh, int field)
{
    struct kfd* kfd = (struct kfd*)kfdh;
    switch (field) {
        case CFM_KDYN_PROC_PID:      return dynamic_info(proc__p_pid);
        case CFM_KDYN_PROC_LE_PREV:  return dynamic_info(proc__p_list__le_prev);
        case CFM_KDYN_TASK_MAP:      return dynamic_info(task__map);
        case CFM_KDYN_PROC_OBJ_SIZE: return dynamic_info(proc__object_size);
        case CFM_KDYN_KREAD_KQUEUE_SUPPORTED:
            return (uint64_t)dynamic_info(kread_kqueue_workloop_ctl_supported);
    }
    return 0;
}

uint64_t cfm_kfd_perf(uint64_t kfdh, int which)
{
    struct kfd* kfd = (struct kfd*)kfdh;
    switch (which) {
        case CFM_KPERF_SLIDE:     return kfd->perf.kernel_slide;
        case CFM_KPERF_GVIRTBASE: return kfd->perf.gVirtBase;
        case CFM_KPERF_GPHYSBASE: return kfd->perf.gPhysBase;
    }
    return 0;
}

// 内核版本表（info_init 就是拿它做精确匹配的，预检用同一张表）
uint64_t cfm_kfd_version_count(void)
{
    return sizeof(kern_versions) / sizeof(kern_versions[0]);
}

const char* cfm_kfd_version_string(uint64_t i)
{
    if (i >= cfm_kfd_version_count()) return "";
    return kern_versions[i].kern_version;
}

// 版本表第 i 项是否支持 kread_kqueue_workloop_ctl（否则必须用 kread_sem_open）
uint64_t cfm_kfd_version_kread_kqueue_supported(uint64_t i)
{
    if (i >= cfm_kfd_version_count()) return 0;
    return (uint64_t)kern_versions[i].kread_kqueue_workloop_ctl_supported;
}

// struct _vm_map 布局（见 libkfd/info/static_info.h）：
//   lock[2]          +0x00
//   hdr.links.prev   +0x10
//   hdr.links.next   +0x18  <- 第一个 vm_map_entry
//   hdr.links.start  +0x20  <- min_offset（最低映射 = 主可执行文件基址）
//   hdr.links.end    +0x28  <- max_offset
//   pmap             +0x38
uint64_t cfm_vmmap_first_entry_offset(void) { return 0x18; }
uint64_t cfm_vmmap_min_offset(void)         { return 0x20; }
uint64_t cfm_vmmap_pmap_offset(void)        { return 0x38; }

int  cfm_kfd_panic_happened(void) { return cfm_kfd_panic_flag; }
void cfm_kfd_panic_reset(void)    { cfm_kfd_panic_flag = 0; }
