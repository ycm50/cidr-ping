
$BUILD_DIR = "build"

if (Test-Path $BUILD_DIR) {
    Remove-Item $BUILD_DIR -Recurse
}

# 生成并编译
cmake -S . -B $BUILD_DIR -G "MinGW Makefiles"
cmake --build $BUILD_DIR

# 移动生成的可执行文件到项目根目录
foreach ($exe in @("cidr-ping.exe", "sort-rtts.exe", "multy_apply.exe")) {
    $src = Join-Path $BUILD_DIR $exe
    if (Test-Path $src) {
        Move-Item -Force $src .
    } else {
        Write-Warning "$exe 未生成"
    }
}

Write-Host "构建完成"