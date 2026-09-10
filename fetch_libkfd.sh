#!/bin/bash
# 拉取公开 kfd PoC 的 libkfd 源码，放入工程供 KernelRW.m 链接
# 在 macOS 上运行（需要 git）
set -e

echo "=== 拉取 libkfd 源码 ==="

# 优先 felix-pb/kfd（binpwn/kfd 同源，含完整 libkfd）
KFD_REPO="${KFD_REPO:-https://github.com/felix-pb/kfd.git}"
DEST="libkfd"

if [ -d "$DEST/.git" ]; then
    echo "已存在 $DEST，跳过 clone"
else
    git clone --depth 1 "$KFD_REPO" "$DEST"
fi

echo ""
echo "=== libkfd 目录结构 ==="
find "$DEST" -maxdepth 2 -type f \( -name "*.c" -o -name "*.h" \) | sort

echo ""
echo "=== 下一步（手动，Xcode 图形界面）==="
echo "1. 打开 CFMCheat.xcodeproj"
echo "2. 把 $DEST/libkfd 目录（或其中的 .c/.h 文件）拖进工程"
echo "3. 在 target 的 Build Settings -> Header Search Paths 加: \$(SRCROOT)/$DEST/libkfd"
echo "4. 编译：./build.sh"
echo ""
echo "注意：KernelRW.m 顶部的 OFF_*/KOFF_* 偏移仍是占位符，"
echo "需按你设备的 kernelcache 校准（或用靶场的 iOS 17/18 偏移表）。"
