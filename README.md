# Telnet Delay Test General

一个用于测试 TCP 连接延迟的命令行工具，支持**单主机**、**IPv4 CIDR 网段**和 **IPv6 CIDR 网段**的随机 IP 生成与并发测试。

- 多线程并发，大幅提升 CIDR 扫描速度
- 非阻塞 `connect()` + `select()` 实现精确 1000ms 超时控制
- 测试前预生成完整测试列表，保证线程安全
- 支持批量文件扫描

## 功能

- 测试任意主机/端口的三次握手延迟
- 解析 IPv4 CIDR（`192.168.1.0/24`）并生成随机 IP 进行扫描
- 解析 IPv6 CIDR（`2400:cb00:2049::/48`）并生成随机 IP 进行扫描
- 多线程并发测试，显著提升扫描效率
- 精确 1000ms 超时（非阻塞 connect + select，不依赖 socket 选项）
- 交互式输入 / 命令行参数 / 批量文件 三种模式
- 结果保存到 `rtts.csv`（UTF-8 BOM，Excel/WPS 直接打开无乱码）
- 配套 `sort-rtts` 按延迟排序输出

## 编译

### 前置要求

| 平台 | 依赖 |
|------|------|
| **Windows** | [MSYS2/MinGW](https://www.msys2.org/)（`pacman -S mingw-w64-ucrt-x86_64-gcc cmake make`） |
| **Linux** | `g++` / `clang++`、`cmake`、`make`（`sudo apt install cmake make g++`） |
| **macOS** | Xcode Command Line Tools（`xcode-select --install`） |

> 不要在有中文路径的目录下编译。

### 快速编译

```bash
# Windows (在 MSYS2/MinGW 终端中运行)
./install.ps1

# Linux / macOS
./install.sh
```

编译完成后，项目根目录下会生成三个可执行文件：

| 可执行文件 | 说明 |
|-----------|------|
| `cidr-ping` | 主程序 — 单主机/IP/CIDR 测试 |
| `sort-rtts` | 排序工具 — 读取 `rtts.csv`，按延迟升序输出到 `rtts_sorted.csv` |
| `multy_apply` | 批量工具 — 从文件读取多个 CIDR 并逐一扫描 |

### 手动编译

```bash
cmake -S . -B build
cmake --build build

# 可执行文件在 build/ 目录下
./build/cidr-ping
```

CMake 选项：

- `-DBUILD_EXECUTABLE=ON`（默认）— 编译 `cidr-ping` 可执行文件
- `-DBUILD_STATIC_LIB=ON` — 编译静态库
- `-DBUILD_SHARED_LIB=ON` — 编译动态库

## 用法

### 命令行模式

```bash
./cidr-ping <主机名/IP/网段> [端口] [生成IP数量]
```

| 参数 | 位置 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| 主机/IP/网段 | 1 | 是 | — | 主机名、IPv4/IPv6 地址，或 CIDR（如 `10.0.0.0/16`） |
| 端口 | 2 | 否 | `443` | 1–65535 |
| 生成 IP 数 | 3 | 否 | `10` | 仅 CIDR 模式有效；单主机模式下忽略 |

**示例：**

```bash
# 测试单主机 (默认端口 443)
./cidr-ping example.com

# 测试单主机 (指定端口)
./cidr-ping 192.168.1.1 8080

# IPv4 网段随机扫描 (10个随机IP，端口443)
./cidr-ping 192.168.1.0/24

# IPv4 网段随机扫描 (50个随机IP，端口22)
./cidr-ping 10.0.0.0/8 22 50

# IPv6 网段随机扫描
./cidr-ping 2400:cb00:2049::/48 443 20
```

### 交互式模式

不传任何参数进入交互模式，每步都有默认值，直接回车使用默认值：

```bash
./cidr-ping
```

```
请输入主机名或IPv6网段(格式如2400:cb00:2049::/48):        ← 回车默认 2400:cb00:2049::/48
请末端口号 (默认443):                                       ← 回车默认 443
请输入生成IP的数量 (默认10):                                 ← 回车默认 10
```

### 批量文件模式

`multy_apply` 从文件逐行读取 CIDR，逐个扫描：

```bash
./multy_apply <cidr文件> <端口> <CIDR数量>
```

**示例 `cidr_list.txt`：**
```
192.168.1.0/24
10.0.0.0/8
2400:cb00:2049::/48
```

```bash
./multy_apply cidr_list.txt 443 5
```

等价于依次执行：

```bash
./cidr-ping 192.168.1.0/24 443 5
./cidr-ping 10.0.0.0/8   443 5
./cidr-ping 2400:cb00:2049::/48 443 5
```

### 排序输出

```bash
./sort-rtts
```

读取 `rtts.csv` → 按延迟升序排列 → 输出到 `rtts_sorted.csv`

## 输出格式

### `rtts.csv`

UTF-8 BOM 编码，四列 CSV：

| 列 | 内容 | 示例 |
|----|------|------|
| ip | 原始 IP 或主机名 | `192.168.1.42` 或 `2400:cb00:2049::1a2b` |
| ip_with_brackets | 格式化 IP（IPv6 加方括号） | `[2400:cb00:2049::1a2b]` |
| ip_port_with_brackets | IP + 端口 | `192.168.1.42:443` 或 `[2400:cb00:2049::1a2b]:443` |
| 延迟 | 毫秒数或错误信息 | `12.34` 或 `连接失败` |

> 文件以覆盖方式写入，每次运行会清空旧结果。UTF-8 BOM 确保 Excel/WPS/ LibreOffice 直接打开时中文字符不乱码。

## 技术架构

```text
cidr_ping_main()
  │
  ├─ 阶段1: 参数解析 + 预生成测试列表
  │   ┌ 单主机 → list = {host}
  │   ├ IPv4 CIDR → generate_random_ipv4() × N → list
  │   └ IPv6 CIDR → generate_random_ipv6() × N → list
  │
  ├─ 阶段2: 打开 CSV（写入 UTF-8 BOM + 表头）
  │
  ├─ 阶段3: 启动线程池
  │   线程数 = min(hardware_concurrency(), 目标数)
  │   ┌─────────────────────────────────────┐
  │   │ Worker 线程 (×N)                     │
  │   │   loop:                              │
  │   │     idx = atomic<size_t>::fetch_add() │
  │   │     if idx ≥ N → break               │
  │   │     test_telnet_delay_nonblock()      │
  │   │     mutex_lock → 写 CSV → mutex_unlock│
  │   └─────────────────────────────────────┘
  │
  └─ 阶段4: join 所有线程 → 关闭 CSV
```

### 超时机制

采用 **非阻塞 connect + select()** 而非 socket 超时选项：

```
socket() → fcntl(F_SETFL, O_NONBLOCK)
  ↓
connect() → 立即返回 (EINPROGRESS)
  ↓
gettimeofday()  ← 测试前开始计时
  ↓
select(fd+1, NULL, &wfds, NULL, {1, 0})  ← 精确 1000ms
  ↓
gettimeofday()  ← 结束计时
  ↓
select == 0   → 超时，记录 "连接失败"
select > 0    → getsockopt(SO_ERROR) 检查连接状态 → 写入延迟
```

优势：不受内核 TCP 连接超时参数影响，始终精确 1000ms。

### 线程安全

| 关注点 | 措施 |
|--------|------|
| `rand()` 非线程安全 | 所有 IP 生成在阶段1（主线程）一次性完成 |
| 任务分配 | `std::atomic<size_t>` 原子递增索引 |
| CSV / 终端输出 | `std::mutex` 保护 `fprintf` + `printf` |
| Socket 操作 | 每个线程独立创建/关闭 socket，无共享 |
| Winsock 初始化 | `WSAStartup`/`WSACleanup` 在每线程 `test_telnet_delay` 内独立调用（引用计数安全） |

## 项目文件

| 文件 | 说明 |
|------|------|
| `cidr-ping.cpp` | 核心实现：非阻塞测试函数 + 线程池 + CIDR 解析 |
| `cidr-ping.h` | 公共头文件，导出 `cidr_ping_main()` 和跨平台宏 |
| `sort-rtts.cpp` | 排序工具，按延迟升序排列 |
| `multy_apply.cpp` | 批量扫描入口，逐行读取文件调用核心 |
| `CMakeLists.txt` | CMake 构建配置（C++11 + Threads） |
| `install.sh` | Linux/macOS 一键编译安装脚本 |
| `install.ps1` | Windows (MSYS2/MinGW) 一键编译安装脚本 |
