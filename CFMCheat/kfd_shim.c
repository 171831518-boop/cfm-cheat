//
//  kfd_shim.c
//  CFMCheat
//
//  libkfd 是 header-only 实现（kopen/kread/kwrite/kclose 定义在 libkfd.h 里）。
//  本 shim 以纯 C 编译包含它，产出 C 链接符号，供 KernelRW.m 的 extern 声明链接。
//

#include "libkfd.h"
