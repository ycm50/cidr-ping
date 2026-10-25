#!/usr/bin/env bash
# cidr-ping 一键编译脚本（Linux / macOS）
#
# 注意：不再无条件 `rm -rf build`。只有确认 build/ 是 CMake 构建目录时才复用它，
# 否则直接报错退出，避免误删用户放在 build/ 里的其它内容。

set -euo pipefail

BUILD_DIR="build"

if [ -d "$BUILD_DIR" ]; then
    if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
        echo "错误: $BUILD_DIR 已存在但不是 CMake 构建目录。" >&2
        echo "      请换一个目录（改本脚本的 BUILD_DIR），或确认后自行删除它。" >&2
        exit 1
    fi
fi

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel

# 复制到项目根目录（保留 build/ 里的产物，便于继续跑 ctest）
for exe in cidr-ping sort-rtts multy_apply; do
    if [ -f "$BUILD_DIR/$exe" ]; then
        cp -f "$BUILD_DIR/$exe" .
    else
        echo "警告: $exe 未生成"
    fi
done

echo "构建完成。"
echo "运行测试: ctest --test-dir $BUILD_DIR --output-on-failure"
echo "单元测试默认开启；交叉编译时请加 -DBUILD_TESTING=OFF。"