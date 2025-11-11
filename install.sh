#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build"

# 如果存在就删除再新建，否则直接新建
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

cd "$BUILD_DIR"

# 清空 build 目录（保险起见只删除内部文件）
rm -rf ./*

# 生成并编译
cmake .. 
make

# 如果可执行文件存在再移动，避免 mv 出错导致脚本退出
if [ -f "cidr-ping" ]; then
    mv -f "cidr-ping" ..
else
    echo "警告: cidr-ping 未生成"
fi

if [ -f "sort-rtts" ]; then
    mv -f "sort-rtts" ..
else
    echo "警告: sort-rtts 未生成"
fi
cd ..

echo "构建完成"
