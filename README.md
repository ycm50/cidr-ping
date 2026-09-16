# Telnet Delay Test General

一个用于测试 **TCP / UDP / WireGuard** 连接延迟的命令行工具，支持**单主机**、**IPv4 CIDR 网段**和 **IPv6 CIDR 网段**的随机采样或**整段枚举**并发测试。

- 测试方式可切换：`--tcp`（默认，三次握手）/ `--udp`（发数据报并等回包）/ `--wg`（发 WireGuard 握手发起包，等真实握手响应）
- 并行测速：IP池（栈结构）+ 多线程并发 pop，大幅提升 CIDR 扫描速度
- 非阻塞 socket + `select()` 实现精确超时控制（默认 1000ms，`--udp-timeout` 可调）
- 互斥锁保护并发出栈，每个 IP 恰好被测一次，不重不漏
- `--full` 整段枚举网段内全部地址，用于「不漏一个」地找可用端点
- 支持批量文件扫描

## 功能

- 测试任意主机/端口的延迟：TCP 三次握手，或 UDP 数据报往返
- `--udp-payload=<hex>` 可指定 UDP 载荷，用于探测需要特定报文才会响应的服务（DNS 等）
- `--wg` 内置完整 WireGuard 握手实现（X25519 + BLAKE2s + HMAC + ChaCha20-Poly1305），
  能真正和 WARP 端点完成握手，用来筛选可用的 WARP endip
- 解析 IPv4 CIDR（`192.168.1.0/24`）并生成随机 IP 进行扫描
- 解析 IPv6 CIDR（`2400:cb00:2049::/48`）并生成随机 IP 进行扫描
- `--full` 整段枚举（IPv4 最多 65536 个，IPv6 需 `/112` 及更长）
- IP池采用栈（`std::stack`）数据类型，多线程 `pop` 并行测速
- 精确超时（非阻塞 socket + select，不依赖 socket 选项）
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
- `-DBUILD_TESTING=OFF` — 关闭单元测试目标（默认 ON，交叉编译时建议关闭）

## 测试

仓库自带一套不依赖第三方框架的测试（`tests/test_cidr_ping.cpp`），默认随构建一起编译：

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

也可以直接运行测试程序查看完整输出（会在工作目录生成/覆盖 `rtts.csv`）：

```bash
cd build && ./cidr-ping-tests
```

覆盖范围：

| 用例 | 校验内容 |
|------|----------|
| `parse_ipv4_prefix` | 合法网段、缺少 `/前缀`、前缀越界、段数不足、段值越界 |
| `generate_random_ipv4` | `/24` 前三段固定、`/32` 唯一地址、`/1` 最高位固定、`/31` 低位随机、`/0` 不触发未定义行为 |
| `parse_ipv6_prefix` / `generate_random_ipv6` | 合法 `/48`、`/128` 完全固定、`/0`、前缀越界、非法地址 |
| `test_telnet_delay` | 真实监听端口必须成功且延迟 <1000ms；无人监听端口必须失败；不存在的主机名必须失败 |
| `test_udp_delay` | UDP 回声服务往返成功（含空数据报）；回声服务确实收到报文；无人监听端口返回“ICMP 不可达”或“超时”；不存在的主机名必须失败 |
| fd/socket 泄漏回归 | 连续 1200 次**成功**连接（fd 号超过 `FD_SETSIZE`）后打开的描述符数量不增长 |
| `cidr_ping_main` 端到端 | 300 个目标恰好 300 行记录、栈式 IP 池被取空、IPv6 分支、库模式不写表头 |
| 参数校验 | 端口 0 / 越界、数量 ≤0、非法 IPv4/IPv6 网段一律返回码 1 |
| `--tcp` / `--udp` 参数解析 | 不带开关时必须是 TCP（不给 UDP 回声服务发报文）；`--udp` 必须真的发 UDP；`--udp-payload` 的十六进制解析；`--help` 返回 0；未知选项与非法载荷返回 1 |
| WireGuard 原语 | BLAKE2s-256 对 RFC 7693 附录 B 向量；X25519 对 RFC 7748 §6.1 向量（DH 与公钥派生）；ChaCha20-Poly1305 对独立实现算出的、nonce 形状与 WireGuard 一致的向量（含 `counter=0` 与 `counter≠0`） |
| WireGuard 握手包 | 148 字节确定性向量逐字节比对（与 `python-cryptography` 独立实现相同）；字段布局（type/reserved/index/mac2）；改时间戳/reserved/index 必须让包变化；`sender_index` 不影响 Noise 载荷但会改 `mac1`；NULL 参数必须失败 |
| `--wg` 参数解析与分发 | 缺私钥 / 非法私钥 / 非法 reserved / 非法 `--udp-timeout` 一律返回 1；`--wg` 必须真的发出 148 字节且首字节为 `0x01`；`--wg-reserved=010203` 必须落在报文第 1~3 字节；默认 reserved 必须为 `000000`；`--wg` 不带端口时默认 `2408`；`--wg` 后再给 `--tcp` 必须改回 TCP；私钥的 hex 与 base64 写法等价 |
| `--full` 整段枚举 | `/30` 恰好 4 行且四个地址都出现；IPv6 `/126` 同样 4 行；`/0`、`/8`、IPv6 `/64` 一律拒绝；`--full` 时不再校验「生成IP数量」但仍校验端口 |

> 测试只使用本机回环地址（`127.0.0.0/8`），不依赖外网。fd 计数仅在 Linux（`/proc/self/fd`）上断言。

## 用法

### 命令行模式

```bash
./cidr-ping [选项] <主机名/IP/网段> [端口] [生成IP数量]
```

**选项：**

| 选项 | 默认 | 说明 |
|------|------|------|
| `--tcp` | ✅ 生效 | 以 TCP 三次握手测速 |
| `--udp` | | 以 UDP 发数据报并等回包测速 |
| `--udp-payload=<hex>` | 空数据报 | UDP 模式发送的载荷，十六进制。分隔符可用 空格/制表/`:`/`,`/`-`/`_`，每字节可带 `0x` 前缀 |
| `--wg` | | 以 WireGuard 握手探测端点（走 UDP，默认端口 `2408`） |
| `--wg-key=<base64\|hex>` | | 本端 WireGuard 私钥（32 字节）。`--wg` 必填，服务端要在自己的 peer 表里找到对应公钥才会回包 |
| `--wg-peer-key=<base64\|hex>` | Cloudflare WARP 公钥 | 对端公钥 |
| `--wg-reserved=<hex>` | `000000` | 握手发起包的 3 字节保留字段。**WARP 必须是全 0**，注册时拿到的 `client_id` 只用于数据包 |
| `--udp-timeout=<ms>` | `1000` | UDP / WireGuard 的总等待预算，按 `50%/30%/20%` 切成 3 轮补发 |
| `--full` | | 整段枚举网段内所有地址（忽略「生成IP数量」）。IPv4 上限 65536 个，IPv6 需 `/112` 及更长 |
| `-h`, `--help` | | 显示帮助并退出（返回码 0） |

`--tcp` / `--udp` / `--wg` 放在位置参数前面或后面都可以，**最后一个生效**；未知选项会打印帮助并以返回码 1 退出。

**位置参数：**

| 参数 | 位置 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| 主机/IP/网段 | 1 | 是 | — | 主机名、IPv4/IPv6 地址，或 CIDR（如 `10.0.0.0/16`） |
| 端口 | 2 | 否 | `443` | 1–65535 |
| 生成 IP 数 | 3 | 否 | `10` | 仅 CIDR 模式有效；单主机模式下忽略 |

**示例：**

```bash
# 测试单主机 (默认 TCP，默认端口 443)
./cidr-ping example.com

# 测试单主机 (指定端口)
./cidr-ping 192.168.1.1 8080

# IPv4 网段随机扫描 (10个随机IP，端口443)
./cidr-ping 192.168.1.0/24

# IPv4 网段随机扫描 (50个随机IP，端口22)
./cidr-ping 10.0.0.0/8 22 50

# IPv6 网段随机扫描
./cidr-ping 2400:cb00:2049::/48 443 20

# UDP 往返测速（默认发空数据报）
./cidr-ping --udp 192.168.1.0/24 53 50

# 带自定义 UDP 载荷：发一个真实的 DNS 查询给 1.1.1.1:53
./cidr-ping --udp \
  --udp-payload=123401000001000000000000076578616d706c6503636f6d0000010001 \
  1.1.1.1 53 1

# 整段枚举（/24 = 256 个地址，一个不漏）
./cidr-ping --full 192.168.1.0/24 443

# 找可用的 Cloudflare WARP 端点：整段扫 162.159.192.0/24 的 2408 端口
./cidr-ping --full --wg --wg-key=<你的 WARP 私钥 base64> 162.159.192.0/24 2408

# 端点有点飘，预算放宽到 2 秒能多捞回一些（实测有 1.2s 才回包的）
./cidr-ping --full --wg --wg-key=<私钥> --udp-timeout=2000 8.47.69.0/24 2408
```

> **UDP 模式说明**：只发一个数据报，收不到任何回包就报 `UDP无响应`；
> 如果收到 ICMP 端口不可达（说明主机在线、只是该端口没有 UDP 服务）则报 `UDP端口不可达`。
> 报文会在超时预算内按 `50%/30%/20%` 补发最多 3 次以对抗 UDP 丢包（默认预算 1000ms，
> 即原来的 `500/300/200ms`）。因此「目标不响应空数据报」是正常结果 ——
> 需要特定报文的协议（DNS 查询等）必须用 `--udp-payload` 给出真实载荷，否则测不出东西；
> 而 WireGuard 这种需要密码学握手的协议，请直接用 `--wg`。

### WireGuard 模式（`--wg`）

`--wg` 用来回答一个 TCP/UDP 都答不了的问题：**这个 UDP 端点上真的跑着 WireGuard，
而且认得我这个公钥吗？**

普通 UDP 探测做不到这件事。WARP 端点对随便一个数据报是不理会的；它只有在同时满足
下面三条时才会回一个 148 字节的握手响应（首字节 `0x02`）：

1. `mac1` 校验通过（说明对方确实掌握我们声明的那把对端公钥）；
2. `encrypted_static` 能解密、且解出来的公钥在服务端的 peer 表里（**所以必须用自己注册过的私钥**）；
3. `encrypted_timestamp` 的时间戳有效（重放保护）。

所以「收到 `0x02`」是端点可用性的强证据，而不是“某个 UDP 端口有回包”这种弱信号。

握手包固定 148 字节，结构如下：

| 偏移 | 长度 | 字段 |
|------|------|------|
| 0 | 1 | 类型 `0x01`（handshake initiation） |
| 1 | 3 | reserved（WARP 必须 `00 00 00`） |
| 4 | 4 | sender index（小端） |
| 8 | 32 | ephemeral public key |
| 40 | 48 | `encrypted_static`（32 字节公钥 + 16 字节 tag） |
| 88 | 28 | `encrypted_timestamp`（12 字节 TAI64N + 16 字节 tag） |
| 116 | 16 | `mac1` |
| 132 | 16 | `mac2`（无 cookie 时全 0） |

配套的密码学原语都在 `wireguard.cpp` 里自己实现（无第三方依赖）：
X25519、BLAKE2s-256、HMAC-BLAKE2s、带密钥的 BLAKE2s-128（`mac1`）、ChaCha20-Poly1305 AEAD。
这些原语和整包的组装都对着 RFC 官方向量 / `python-cryptography` 独立实现逐字节校对过（见测试表）。

**拿私钥**：`--wg-key` 接受 base64（44 字符）或 64 位十六进制。消费级 WARP 的私钥可以
用 `wg genkey` 生成任意一把后调 `https://api.cloudflareclient.com/v0a2158/reg` 注册获得
（注册时返回的 `client_id` 是给**数据包**用的 reserved，握手发起包仍必须填 `000000`）。

**结果解读**：

| 输出 / CSV | 含义 |
|------------|------|
| `WireGuard 握手响应(0x02)` | ✅ 真端点：mac1、peer 查询、时间戳全部通过 |
| `WireGuard Cookie回复(0x03)` | 服务端在限流，但它确实是 WireGuard，且认得我们的公钥 |
| `WireGuard 传输数据(0x04)` | 收到了类型 4 的报文（正常握手探测不会出现） |
| `WG回包(0x??)` | 收到了首字节既不是 1/2/3/4 的报文 |
| `WG无响应` | 预算内没有回包（端点不通 / 不认这把密钥 / 丢包） |
| `WG端口不可达` | 收到 ICMP：主机在线，但该 UDP 端口没有服务 |

> **端点抖动是常态**。同一个 IP 上一分钟能回 `0x02`、下一分钟就没反应；
> 实测同一批 8 个已知可用的 IP，Python 参考实现捞回 4 个、本工具（预算 2s）捞回 7 个。
> 所以「扫到就记下来」比「一次没扫到就判死」更符合实际，多轮扫描取并集最稳。

### 交互式模式

不传任何参数进入交互模式，每步都有默认值，直接回车使用默认值：

```bash
./cidr-ping
```

```
请输入主机名或IPv6网段(格式如2400:cb00:2049::/48):        ← 回车默认 2400:cb00:2049::/48
请末端口号 (默认443):                                       ← 回车默认 443
请输入生成IP的数量 (默认10):                                 ← 回车默认 10
请选择测试方式 [1] TCP [2] UDP [3] WireGuard (默认1):        ← 回车默认 TCP
```

> 测试方式问句放在最后，所以以前「喂三行输入」的脚本仍然有效：
> 第四行读不到时保持命令行上 `--tcp` / `--udp` / `--wg` 给出的默认值。
> 例如 `./cidr-ping --udp` 不带位置参数时进入交互模式，测试方式默认就是 UDP。
>
> 只有选了第 3 种（WireGuard）且命令行上没给过 `--wg-key` 时，才会再追问一行私钥；
> 前四种输入的脚本完全不受影响。

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

> `multy_apply` 固定以默认的 TCP 模式调用核心，不接受 `--tcp` / `--udp` 开关。

### 排序输出

```bash
./sort-rtts
```

读取 `rtts.csv` → 按延迟升序排列 → 输出到 `rtts_sorted.csv`（只输出 ip 与延迟两列）

- `WG握手响应(0x02)@215.45` 这种带 `@` 的行会取 `@` 后面的数字当作延迟
- 没有延迟可解析的行（`连接失败`、`UDP无响应`、`WG无响应` 等）会被跳过，并在结束时报告跳过了几行

## 输出格式

### `rtts.csv`

UTF-8 BOM 编码，四列 CSV：

| 列 | 内容 | 示例 |
|----|------|------|
| ip | 原始 IP 或主机名 | `192.168.1.42` 或 `2400:cb00:2049::1a2b` |
| ip_with_brackets | 格式化 IP（IPv6 加方括号） | `[2400:cb00:2049::1a2b]` |
| ip_port_with_brackets | IP + 端口 | `192.168.1.42:443` 或 `[2400:cb00:2049::1a2b]:443` |
| 延迟 | 毫秒数或错误信息 | `12.34`、`连接失败`、`UDP无响应`、`WG握手响应(0x02)@215.45` |

失败原因文字对照：

| 文字 | 含义 |
|------|------|
| `无法解析主机名` | `getaddrinfo` 失败 |
| `连接失败` | TCP 连接失败 / UDP 发送失败 / 解析后无可用地址 |
| `UDP无响应` | UDP 在超时预算内（含 3 次补发）未收到任何回包 |
| `UDP端口不可达` | 收到 ICMP 端口不可达：主机在线，但该 UDP 端口没有服务 |
| `WG握手响应(0x02)@<ms>` | WireGuard 握手成功，`@` 后面是往返毫秒数 |
| `WGCookie回复(0x03)` / `WG传输数据(0x04)` / `WG回包(0x??)` | 收到 WireGuard 报文，但首字节不是 `0x02` |
| `WG无响应` | WireGuard 握手在预算内没等到回包 |
| `WG端口不可达` | 收到 ICMP 端口不可达：主机在线，但该 UDP 端口没有服务 |

> 文件以覆盖方式写入，每次运行会清空旧结果。UTF-8 BOM 确保 Excel/WPS/ LibreOffice 直接打开时中文字符不乱码。

## 技术架构

```text
cidr_ping_main()
  │
  ├─ 阶段0: 参数解析
  │   ┌ 先摘出 --tcp/--udp/--wg/--full/--udp-payload/--udp-timeout/--wg-* 等开关
  │   ├ 其余按位置解释为 <主机/网段> [端口] [数量]
  │   └ --wg 时组装一次 148 字节握手包（所有目标共用）并打印本端公钥
  │
  ├─ 阶段1: 建立IP池（栈）
  │   ├ 单主机 → push(host)
  │   ├ IPv4 CIDR → generate_random_ipv4() × N → push 入栈
  │   │              或 --full → 从 network 起整段枚举 2^(32-len) 个 → push 入栈
  │   └ IPv6 CIDR → generate_random_ipv6() × N → push 入栈
  │                 或 --full（/112 及更长）→ 整段枚举 → push 入栈
  │   IP池类型: std::stack<TestTarget>（LIFO 后进先出）
  │
  ├─ 阶段2: 打开 CSV（写入 UTF-8 BOM + 表头）
  │
  ├─ 阶段3: 启动线程池并行测速
  │   线程数 = min(hardware_concurrency(), IP池目标数)
  │   ┌────────────────────────────────────────────────────────┐
  │   │ Worker 线程 (×N)                                        │
  │   │   loop:                                                 │
  │   │     lock(pool_mutex)          ← 并发出栈锁               │
  │   │       if ip_pool.empty() → break                        │
  │   │       target = ip_pool.top()                            │
  │   │       ip_pool.pop()                                     │
  │   │     unlock(pool_mutex)                                  │
  │   │     test_target_delay()            ← 锁外并行测速        │
  │   │       ├ TCP: 非阻塞 connect() + select()                │
  │   │       └ UDP/WG: connect() 定目标 + send() + select()/recv()
  │   │                （WG 额外带回回包首字节用于判定 0x02）        │
  │   │     lock(io_mutex) → 写 CSV/终端 → unlock                │
  │   └────────────────────────────────────────────────────────┘
  │
  └─ 阶段4: join 所有线程 → 关闭 CSV
```

> UDP 与 WireGuard **共用同一条传输路径**（`test_udp_delay`）：都是「connect() 固定目标 →
> 按预算补发 → select() 等回包」。区别只在载荷（WG 是 148 字节握手发起包）
> 和结果解读（WG 会看回包首字节）。这样 WG 模式自动继承了 UDP 模式已经测过的
> 非阻塞 / ICMP 区分 / 超时兜底逻辑。

### IP池与并行模型

- **IP池（栈）**：阶段1 由主线程一次性生成全部待测 IP 并 `push` 进 `std::stack<TestTarget>`。
  采用栈（LIFO）语义，线程总是从栈顶取最近压入的 IP。
- **并发出栈加锁**：`std::stack` 本身不是线程安全的，多个线程同时 `pop` 会破坏容器内部状态，
  导致 IP 丢失、重复测速甚至崩溃。因此所有 `top()` / `pop()` 都放在
  `std::lock_guard<std::mutex>` 临界区内，任一时刻只有一个线程能出栈。
- **锁粒度最小化**：出栈拿到 IP 后立即释放锁，耗时的网络测速在锁外进行，
  因此锁不会把并行测速串行化——线程数越多吞吐越高。
- **不重不漏**：每个 IP 出栈后只归当前线程所有，实测 2000 目标下 CSV 恰好 2000 条记录、
  测速结束后栈为空。
- **随机采样 vs 整段枚举**：默认走老行为——在网段内随机取 N 个地址（`rand()` 只在阶段1
  的单线程里调用）。要「一个不漏」就用 `--full`，它按 `network` 起顺序枚举整个网段，
  目标数由前缀长度决定（`/24` → 256 个）。找可用端点时 `--full` 明显更划算：
  随机采样要凑到接近全覆盖得 draw 约 `N·ln N` 次，而整段枚举正好 `N` 次。

### 超时机制

两种模式都用 **非阻塞 socket + select()** 而非 socket 超时选项；TCP 的超时上限为 **1000ms**，
UDP / WireGuard 的等待预算由 `--udp-timeout` 决定（默认 **1000ms**，按 `50%/30%/20%` 切成 3 轮）。

**TCP（默认）**

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

**UDP（`--udp`）/ WireGuard（`--wg`）**

```
socket(SOCK_DGRAM) → fcntl(F_SETFL, O_NONBLOCK)
  ↓
connect()  ← 固定对端，不产生流量；只有已连接的 UDP socket 才能收到 ICMP 差错
  ↓
循环最多 3 次: send(载荷) → select(fd+1, &rfds, NULL, NULL, 预算×50%/30%/20%)
  ↓
recv() ≥ 0            → 收到回包，写入延迟（WG 模式同时记下首字节）
recv() ECONNREFUSED   → ICMP 端口不可达，记录 "UDP/WG端口不可达"（主机在线）
recv() EAGAIN         → 本轮没数据，继续下一轮补发
3 轮全部无数据        → 记录 "UDP/WG无响应"
```

优势：不受内核 TCP 连接超时参数影响，超时始终精确。

> 注意 `select()` 的第 2 个参数才是 readfds，第 3 个是 writefds。
> UDP 永远可写，如果把 fd_set 传错位置，`select()` 会立刻返回、
> 随后阻塞在 `recv()` 上——这正是非阻塞 socket 在这里的兜底价值。

### 线程安全

| 关注点 | 措施 |
|--------|------|
| `rand()` 非线程安全 | 所有 IP 生成在阶段1（主线程）一次性完成并压栈 |
| IP池并发出栈 | `std::mutex pool_mutex` + `std::lock_guard` 保护 `top()`/`pop()` |
| 测速并行度 | 锁仅覆盖出栈动作，网络测速在锁外执行，不互相阻塞 |
| 进度计数 | `std::atomic<size_t> tested_count`（仅用于显示 `[n/total]`） |
| CSV / 终端输出 | `std::mutex io_mutex` 保护 `fprintf` + `printf` |
| Socket 操作 | 每个线程独立创建/关闭 socket，无共享 |
| UDP / WG 载荷 | 只读的 `const std::vector<unsigned char>`，线程间只读共享（WG 的握手包在阶段0 组装一次） |
| WireGuard 回包类型 | 每个 worker 用自己栈上的 `unsigned char` 承接，再由 `io_mutex` 保护着写出去 |
| Winsock 初始化 | `WSAStartup`/`WSACleanup` 在每线程 `test_telnet_delay`/`test_udp_delay` 内独立调用（引用计数安全） |

## CI 与发布

`.github/workflows/build.yml` 覆盖 9 个平台：

| 平台标识 | 构建方式 | libc 基线 |
|----------|----------|-----------|
| `linux-x86_64` | GitHub 原生 runner `ubuntu-22.04` | glibc 2.35 |
| `linux-aarch64` | GitHub 原生 runner `ubuntu-22.04-arm` | glibc 2.35 |
| `linux-armv7l` | `arm32v7/debian:12` + QEMU | glibc 2.36 |
| `linux-i686` | `i386/debian:12` + QEMU | glibc 2.36 |
| `linux-riscv64` | `riscv64/ubuntu:24.04` + QEMU | glibc 2.39 |
| `windows-x86_64` | llvm-mingw 交叉编译（UCRT，静态单文件） | 无动态运行库依赖 |
| `windows-aarch64` | 同上 | 无动态运行库依赖 |
| `termux-aarch64` | `termux/termux-docker:aarch64` + QEMU | bionic + libc++ |
| `termux-arm` | `termux/termux-docker:arm` + QEMU | bionic + libc++ |

触发行为：

| 事件 | 行为 |
|------|------|
| push 到 `main` / `master` | 全平台编译 + 单元测试 + 上传 artifact（不发 Release） |
| Pull Request | 只跑 `linux-native` 与 `windows` 两组，跳过重型（模拟）任务 |
| push tag（`v*` 或 `1.0` 形式） | 全平台编译 + 测试 + 打包 + 创建 GitHub Release |
| 手动 `workflow_dispatch` | 自动递增版本号并发布，也可以手填 tag |

自动递增规则：`v1.0 → v1.1 → … → v1.9 → v2.0 → … → v2.9 → v3.0`（minor 到 9 后进位 major）。
产物统一命名为 `cidr-ping-<tag>-<平台>.zip`，非发布场景 `<tag>` 为 `dev-<短 sha>`。

Windows 交叉产物无法在 Linux runner 上执行，因此该 job 传 `-DBUILD_TESTING=OFF`，
改为用工具链自带的 `llvm-objdump -p` / `llvm-nm` 校验可执行文件不依赖
`libstdc++-6.dll` / `libgcc_s_*.dll` / `libwinpthread-1.dll`，并导出 `cidr_ping_main`。
（系统 binutils 读不了 ARM64 PE，必须用 llvm 版本。）

## 项目文件

| 文件 | 说明 |
|------|------|
| `cidr-ping.cpp` | 核心实现：TCP / UDP / WG 测速函数 + IP池（栈）+ 多线程并行测速 + CIDR 解析 + 参数解析 |
| `cidr-ping.h` | 公共头文件，导出 `cidr_ping_main()` 和跨平台宏 |
| `wireguard.h` / `wireguard.cpp` | 自包含的 WireGuard 握手实现：X25519、BLAKE2s、HMAC-BLAKE2s、ChaCha20-Poly1305、148 字节握手包组装 |
| `sort-rtts.cpp` | 排序工具，按延迟升序排列 |
| `multy_apply.cpp` | 批量扫描入口，逐行读取文件调用核心 |
| `tests/test_cidr_ping.cpp` | 单元/集成测试（无第三方依赖，`ctest` 驱动） |
| `CMakeLists.txt` | CMake 构建配置（C++11 + Threads + CTest） |
| `.github/workflows/build.yml` | 多平台构建 / 测试 / 发布流水线 |
| `install.sh` | Linux/macOS 一键编译安装脚本 |
| `install.ps1` | Windows (MSYS2/MinGW) 一键编译安装脚本 |
