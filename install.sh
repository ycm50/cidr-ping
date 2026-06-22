#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="build"

# 删除旧的构建目录
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi

# 生成并编译
cmake -S . -B "$BUILD_DIR"
cmake --build "$BUILD_DIR"

# 移动生成的可执行文件到项目根目录
for exe in cidr-ping sort-rtts multy_apply; do
    if [ -f "$BUILD_DIR/$exe" ]; then
        mv -f "$BUILD_DIR/$exe" .
    else
        echo "警告: $exe 未生成"
    fi
done

echo "构建完成"
