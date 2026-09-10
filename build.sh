#!/bin/bash
# CFMCheat 编译打包脚本（在 macOS + Xcode 上运行）
# 产出：CFMCheat.ipa

set -e

PROJECT="CFMCheat.xcodeproj"
SCHEME="CFMCheat"
CONFIG="Release"
SDK="iphoneos"

echo "=== 1. 编译 arm64 ==="
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration "$CONFIG" \
  -sdk "$SDK" \
  -arch arm64 \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  build

APP_DIR=$(find ~/Library/Developer/Xcode/DerivedData -name "CFMCheat.app" -path "*Release-iphoneos*" | head -1)
if [ -z "$APP_DIR" ]; then
  echo "未找到编译产物 CFMCheat.app"
  exit 1
fi
echo "=== 2. 编译产物: $APP_DIR ==="

# 创建 Payload 目录
BUILD_DIR="build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/Payload"
cp -R "$APP_DIR" "$BUILD_DIR/Payload/"

echo "=== 3. 打包 IPA ==="
cd "$BUILD_DIR"
zip -qry "../CFMCheat.ipa" Payload
cd ..

echo "=== 4. 完成: CFMCheat.ipa ==="
ls -la CFMCheat.ipa

echo ""
echo "=== 安装说明 ==="
echo "1. 普通机（免越狱）：TrollStore / SideStore / 爱思助手重签安装"
echo "   点「获取 root」= kfd 提权拿 KRW，免越狱读写游戏"
echo "2. 越狱设备：Filza 直接装，或 ldid 重签"
echo "3. 前提：必须先把 libkfd 源码引入 Xcode 工程（见 README）"
echo "4. 内核偏移 OFFSETS 在 KernelRW.m 顶部，按设备 kernelcache 校准"
echo "5. 游戏进程名/偏移链在 CheatLoop.m 里配置"
