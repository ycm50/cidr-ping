# cidr-ping 一键编译脚本（Windows / MSYS2 MinGW）
#
# 注意：不再无条件删除 build 目录。只有确认它是 CMake 构建目录时才复用，
# 否则直接报错退出，避免误删用户放在 build/ 里的其它内容。

$ErrorActionPreference = "Stop"
$BUILD_DIR = "build"

if (Test-Path $BUILD_DIR) {
    if (-not (Test-Path (Join-Path $BUILD_DIR "CMakeCache.txt"))) {
        Write-Error "$BUILD_DIR 已存在但不是 CMake 构建目录。请换一个目录（改脚本里的 `$BUILD_DIR`），或确认后自行删除它。"
        exit 1
    }
}

cmake -S . -B $BUILD_DIR -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $BUILD_DIR --parallel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 复制到项目根目录（保留 build/ 里的产物，便于继续跑 ctest）
foreach ($exe in @("cidr-ping.exe", "sort-rtts.exe", "multy_apply.exe")) {
    $src = Join-Path $BUILD_DIR $exe
    if (Test-Path $src) {
        Copy-Item -Force $src .
    } else {
        Write-Warning "$exe 未生成"
    }
}

Write-Host "构建完成。"
Write-Host "运行测试: ctest --test-dir $BUILD_DIR --output-on-failure"