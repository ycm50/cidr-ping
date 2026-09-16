// tests/test_cidr_ping.cpp
//
// cidr-ping 单元 / 集成测试（无第三方框架，C++11，Windows + POSIX 均可编译）
//
// 覆盖点：
//   1. CIDR 解析与随机 IP 生成（IPv4 / IPv6 两条分支，含边界前缀长度）
//   2. TCP 测速核心：连接成功 / 连接被拒绝 / 延迟取值合理
//   3. UDP 测速核心：往返成功 / 无人监听端口（ICMP 不可达或超时）
//   4. 回归“连接成功路径 fd 泄漏”：早期版本 connect() 成功后忘记 close()，
//      Linux 上连续第 1001 次成功会让 fd 号 >= FD_SETSIZE，
//      glibc 的 __fdelt_chk 直接 abort（"bit out of range 0 - FD_SETSIZE"）
//   5. --tcp / --udp / --udp-payload / --help 的参数解析与协议分发
//   6. 端到端跑 cidr_ping_main：栈式 IP 池必须被试空、CSV 数据行数必须等于目标数、
//      库模式（未定义 MAIN）不得写表头
//
// 全部用例只使用本机回环地址，不依赖外网。

#include "cidr-ping.h"
#include "wireguard.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define sock_close close
typedef socklen_t sock_len_t;
#else
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
#define sock_close closesocket
typedef int sock_len_t;
#endif

// ---------------------------------------------------------------------------
// cidr-ping.cpp 中这些函数具有外部链接但未在头文件中声明，这里补上声明用于测试。
// 签名必须与源文件完全一致，否则链接时报错。
// ---------------------------------------------------------------------------
int  parse_ipv4_prefix(const char *prefix_str, unsigned int *ipv4_addr, int *prefix_len);
int  parse_ipv6_prefix(const char *prefix_str, unsigned char *prefix, int *prefix_len);
void generate_random_ipv4(unsigned int ipv4_addr, int prefix_len, char *output, size_t output_size);
void generate_random_ipv6(const unsigned char *prefix, int prefix_len, char *output, size_t output_size);
int  test_telnet_delay(const char *hostname, int port, double *delay_ms);
int  test_udp_delay(const char *hostname, int port, const unsigned char *payload,
                    size_t payload_len, double *delay_ms,
                    unsigned char *resp_type, double budget_ms);
int  test_target_delay(const char *hostname, int port, int protocol,
                       const unsigned char *udp_payload, size_t udp_payload_len,
                       double *delay_ms, unsigned char *resp_type, double budget_ms);

// 与 cidr-ping.cpp 内部的返回码 / 协议枚举保持一致
// （这些符号没有导出到头文件，测试侧只能自己镜像一份）
static const int RP_OK          = 0;
static const int RP_UDP_TIMEOUT = -5;
static const int RP_UDP_ICMP    = -6;
static const int RP_PROTO_TCP   = 0;
static const int RP_PROTO_UDP   = 1;
static const int RP_PROTO_WG    = 2;

// UDP / WireGuard 的超时预算（毫秒），与 cidr-ping.cpp 的默认值一致
static const double RP_BUDGET_MS = 1000.0;

// 空载荷探针：给 send() 一个永远合法的指针，长度传 0
static const unsigned char kEmptyProbe[1] = {0};

// ---------------------------------------------------------------------------
// 极简测试框架
// ---------------------------------------------------------------------------
static int g_pass = 0;
static int g_fail = 0;

#define SECTION(name) printf("\n== %s\n", (name))

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (cond) {                                                        \
            ++g_pass;                                                      \
        } else {                                                           \
            ++g_fail;                                                      \
            printf("   [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                  \
    } while (0)

#define CHECK_EQ(actual, expected)                                         \
    do {                                                                   \
        long long a_ = (long long)(actual);                                \
        long long e_ = (long long)(expected);                              \
        if (a_ == e_) {                                                    \
            ++g_pass;                                                      \
        } else {                                                           \
            ++g_fail;                                                      \
            printf("   [FAIL] %s:%d: %s = %lld, 期望 %lld\n",              \
                   __FILE__, __LINE__, #actual, a_, e_);                   \
        }                                                                  \
    } while (0)

// 字符串版本：CHECK_EQ 会把两边强转成 long long，对 std::string 不适用
#define CHECK_STREQ(actual, expected)                                      \
    do {                                                                   \
        std::string a_ = (actual);                                         \
        std::string e_ = (expected);                                       \
        if (a_ == e_) {                                                    \
            ++g_pass;                                                      \
        } else {                                                           \
            ++g_fail;                                                      \
            printf("   [FAIL] %s:%d: %s\n          实际 %s\n          期望 %s\n", \
                   __FILE__, __LINE__, #actual, a_.c_str(), e_.c_str());   \
        }                                                                  \
    } while (0)

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------
static std::string s_port(int port) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", port);
    return std::string(buf);
}

// 统计 rtts.csv 的数据行数（自动跳过 UTF-8 BOM 与可选的表头行）
static int count_csv_rows(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;

    char line[4096];
    int rows = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n == 0) continue;

        const char *p = line;
        if (n >= 3 && (unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB &&
            (unsigned char)p[2] == 0xBF) {
            p += 3;
        }
        if (strncmp(p, "ip,ip_with_brackets", 19) == 0) continue; // 表头
        ++rows;
    }
    fclose(f);
    return rows;
}

// 读取 rtts.csv 第一行（去 BOM），用于判断是否写了表头
static std::string first_csv_line(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return std::string();
    char line[4096];
    std::string out;
    if (fgets(line, sizeof(line), f) != NULL) out = line;
    fclose(f);

    while (!out.empty() && (out[out.size() - 1] == '\n' || out[out.size() - 1] == '\r')) {
        out.erase(out.size() - 1);
    }
    if (out.size() >= 3 && (unsigned char)out[0] == 0xEF && (unsigned char)out[1] == 0xBB &&
        (unsigned char)out[2] == 0xBF) {
        out.erase(0, 3);
    }
    return out;
}

// rtts.csv 里是否出现过某个子串（多线程写盘顺序不定，只能这样断言内容）
static bool csv_contains(const char *path, const char *needle) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    char line[4096];
    bool found = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) { found = true; break; }
    }
    fclose(f);
    return found;
}

// 在回环地址上开一个监听端口（监听 INADDR_ANY，这样 127.0.0.0/8 全可连通）
static bool listener_start(sock_t *out_fd, int *out_port) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
#endif

    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == SOCK_INVALID) return false;

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return false;
    }
    if (listen(fd, 512) != 0) {
        sock_close(fd);
        return false;
    }

    sock_len_t len = (sock_len_t)sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        sock_close(fd);
        return false;
    }

    *out_fd = fd;
    *out_port = (int)ntohs(addr.sin_port);
    return true;
}

// 后台 accept 线程：只负责把连接收掉再关闭，避免握手队列被塞满导致客户端超时
struct AcceptLoop {
    std::atomic<bool> stop;
    std::thread th;

    static void run(sock_t fd, std::atomic<bool> *stop_flag) {
        while (!stop_flag->load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            int r = select((int)fd + 1, &rfds, NULL, NULL, &tv);
            if (r <= 0) continue;
            sock_t c = accept(fd, NULL, NULL);
            if (c != SOCK_INVALID) sock_close(c);
        }
    }

    void start(sock_t fd) {
        stop.store(false);
        th = std::thread(run, fd, &stop);
    }
    void finish() {
        stop.store(true);
        if (th.joinable()) th.join();
    }
};

// 回环上的 UDP 回声服务：收到任意报文（含 0 字节数据报）就回一个 "pong"。
// 绑定 INADDR_ANY 而不是 127.0.0.1 —— 和 listener_start() 同样的理由：
// 这样 127.0.0.0/8 里的任意地址都能送达，端到端用例才能用整段网段。
struct UdpEchoServer {
    sock_t fd;
    int port;
    std::atomic<bool> stop;
    std::atomic<int> recv_count;
    std::atomic<int> last_len;    // 最近一次收到的报文长度
    std::atomic<int> last_first;  // 最近一次收到的报文首字节
    std::atomic<unsigned long long> last_head64; // 最近一次收到报文的前 8 字节（小端打包）
    std::atomic<int> reply_first; // 回包首字节，默认 'p'（整体即 "pong"）
    std::thread th;

    UdpEchoServer() : fd(SOCK_INVALID), port(0), stop(false), recv_count(0),
                      last_len(-1), last_first(-1), last_head64(0), reply_first('p') {}

    static void run(sock_t fd, std::atomic<bool> *stop_flag, std::atomic<int> *counter,
                    std::atomic<int> *last_len, std::atomic<int> *last_first,
                    std::atomic<unsigned long long> *last_head64,
                    std::atomic<int> *reply_first) {
        while (!stop_flag->load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            int r = select((int)fd + 1, &rfds, NULL, NULL, &tv);
            if (r <= 0) continue;

            char buf[512];
            struct sockaddr_storage from;
            sock_len_t flen = (sock_len_t)sizeof(from);
            int n = (int)recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n < 0) continue;

            counter->fetch_add(1);
            last_len->store(n);
            last_first->store(n >= 1 ? (unsigned char)buf[0] : -1);
            unsigned long long head = 0;
            for (int i = 0; i < 8 && i < n; ++i) {
                head |= ((unsigned long long)(unsigned char)buf[i]) << (8 * i);
            }
            last_head64->store(head);

            // 回包内容固定（首字节可配），客户端只关心“有没有回包”和往返耗时
            char out[4];
            out[0] = (char)(reply_first->load() & 0xff);
            memcpy(out + 1, "ong", 3);
            sendto(fd, out, sizeof(out), 0, (struct sockaddr *)&from, flen);
        }
    }

    bool start() {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
#endif
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == SOCK_INVALID) return false;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(0);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            sock_close(fd);
            fd = SOCK_INVALID;
            return false;
        }

        sock_len_t len = (sock_len_t)sizeof(addr);
        if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
            sock_close(fd);
            fd = SOCK_INVALID;
            return false;
        }
        port = (int)ntohs(addr.sin_port);

        recv_count.store(0);
        last_len.store(-1);
        last_first.store(-1);
        last_head64.store(0);
        stop.store(false);
        th = std::thread(run, fd, &stop, &recv_count, &last_len, &last_first,
                         &last_head64, &reply_first);
        return true;
    }

    void finish() {
        stop.store(true);
        if (th.joinable()) th.join();
        if (fd != SOCK_INVALID) {
            sock_close(fd);
            fd = SOCK_INVALID;
        }
    }
};

// 取一个“刚刚被释放”的 UDP 端口：绑定后再立刻关闭，
// 内核回收之后这个端口上不会有任何服务监听
static bool grab_closed_udp_port(int *out_port) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
#endif
    sock_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == SOCK_INVALID) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sock_close(fd);
        return false;
    }

    sock_len_t len = (sock_len_t)sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        sock_close(fd);
        return false;
    }
    *out_port = (int)ntohs(addr.sin_port);
    sock_close(fd);
    return true;
}

#ifndef _WIN32
// Linux: 直接数 /proc/self/fd —— fd 泄漏回归最直接的证据
static int count_open_fds() {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        ++n;
    }
    closedir(d);
    return n;
}
#endif

// 调用被测入口（不经过进程，直接调用导出函数）
static int run_main(const std::vector<std::string> &args) {
    std::vector<std::string> keep = args;
    keep.reserve(args.size() + 1);
    std::vector<char *> argv;
    argv.reserve(keep.size() + 1);
    for (size_t i = 0; i < keep.size(); ++i) argv.push_back(const_cast<char *>(keep[i].c_str()));
    argv.push_back(NULL);
    return cidr_ping_main((int)keep.size(), &argv[0]);
}

// ---------------------------------------------------------------------------
// 1. IPv4 CIDR 解析
// ---------------------------------------------------------------------------
static void test_parse_ipv4_prefix() {
    SECTION("parse_ipv4_prefix");

    unsigned int addr = 0;
    int plen = -1;

    CHECK_EQ(parse_ipv4_prefix("192.168.1.0/24", &addr, &plen), 0);
    CHECK_EQ(plen, 24);
    CHECK_EQ(ntohl(addr), 0xC0A80100u);

    CHECK_EQ(parse_ipv4_prefix("0.0.0.0/0", &addr, &plen), 0);
    CHECK_EQ(plen, 0);
    CHECK_EQ(ntohl(addr), 0u);

    CHECK_EQ(parse_ipv4_prefix("255.255.255.255/32", &addr, &plen), 0);
    CHECK_EQ(plen, 32);
    CHECK_EQ(ntohl(addr), 0xFFFFFFFFu);

    // 错误分支
    CHECK_EQ(parse_ipv4_prefix("192.168.1.0", &addr, &plen), -1);   // 缺 /前缀
    CHECK_EQ(parse_ipv4_prefix("192.168.1.0/33", &addr, &plen), -2); // 前缀越界
    CHECK_EQ(parse_ipv4_prefix("1.2.3/24", &addr, &plen), -3);      // 段数不足
    CHECK_EQ(parse_ipv4_prefix("1.2.3.256/24", &addr, &plen), -3);  // 段值越界
}

// ---------------------------------------------------------------------------
// 2. 随机 IPv4 生成（必须落在网段内、文本必须可回解析）
// ---------------------------------------------------------------------------
static void test_generate_random_ipv4() {
    SECTION("generate_random_ipv4");

    char buf[64];
    unsigned int addr = 0;
    int plen = 0;
    struct in_addr a;

    // /24：前三段固定
    CHECK_EQ(parse_ipv4_prefix("192.168.1.0/24", &addr, &plen), 0);
    bool ok = true;
    for (int i = 0; i < 300; ++i) {
        generate_random_ipv4(addr, plen, buf, sizeof(buf));
        if (strncmp(buf, "192.168.1.", 10) != 0) { ok = false; break; }
        if (inet_pton(AF_INET, buf, &a) != 1) { ok = false; break; }
        if ((ntohl(a.s_addr) & 0xFFFFFF00u) != 0xC0A80100u) { ok = false; break; }
    }
    CHECK(ok);

    // /32：只能是那一个地址
    CHECK_EQ(parse_ipv4_prefix("10.0.0.7/32", &addr, &plen), 0);
    generate_random_ipv4(addr, plen, buf, sizeof(buf));
    CHECK(strcmp(buf, "10.0.0.7") == 0);

    // /0：任意地址都必须合法
    // 注意：早期实现用 0xFFFFFFFF << (32 - 0)，即 32 位左移 32 位，是未定义行为
    CHECK_EQ(parse_ipv4_prefix("0.0.0.0/0", &addr, &plen), 0);
    ok = true;
    for (int i = 0; i < 100; ++i) {
        generate_random_ipv4(addr, plen, buf, sizeof(buf));
        if (inet_pton(AF_INET, buf, &a) != 1) { ok = false; break; }
    }
    CHECK(ok);

    // /1：最高位必须固定为 1
    CHECK_EQ(parse_ipv4_prefix("128.0.0.0/1", &addr, &plen), 0);
    ok = true;
    for (int i = 0; i < 100; ++i) {
        generate_random_ipv4(addr, plen, buf, sizeof(buf));
        if (inet_pton(AF_INET, buf, &a) != 1) { ok = false; break; }
        if ((ntohl(a.s_addr) & 0x80000000u) != 0x80000000u) { ok = false; break; }
    }
    CHECK(ok);

    // /31：后 31 位随机，首位固定为 0
    CHECK_EQ(parse_ipv4_prefix("0.0.0.0/31", &addr, &plen), 0);
    ok = true;
    for (int i = 0; i < 100; ++i) {
        generate_random_ipv4(addr, plen, buf, sizeof(buf));
        if (inet_pton(AF_INET, buf, &a) != 1) { ok = false; break; }
        if ((ntohl(a.s_addr) & 0xFFFFFFFEu) != 0u) { ok = false; break; }
    }
    CHECK(ok);
}

// ---------------------------------------------------------------------------
// 3. IPv6 CIDR 解析与随机生成
// ---------------------------------------------------------------------------
static void test_ipv6() {
    SECTION("parse_ipv6_prefix / generate_random_ipv6");

    unsigned char prefix[16];
    int plen = -1;
    memset(prefix, 0, sizeof(prefix));

    CHECK_EQ(parse_ipv6_prefix("2400:cb00:2049::/48", prefix, &plen), 0);
    CHECK_EQ(plen, 48);
    CHECK_EQ(prefix[0], 0x24);
    CHECK_EQ(prefix[1], 0x00);
    CHECK_EQ(prefix[2], 0xcb);
    CHECK_EQ(prefix[3], 0x00);
    CHECK_EQ(prefix[4], 0x20);
    CHECK_EQ(prefix[5], 0x49);

    // /48：前 6 字节必须固定
    char buf[64];
    struct in6_addr a;
    bool ok = true;
    for (int i = 0; i < 200; ++i) {
        generate_random_ipv6(prefix, plen, buf, sizeof(buf));
        if (inet_pton(AF_INET6, buf, &a) != 1) { ok = false; break; }
        if (memcmp(&a, prefix, 6) != 0) { ok = false; break; }
    }
    CHECK(ok);

    // /128：必须与前缀完全一致
    CHECK_EQ(parse_ipv6_prefix("2001:db8::1/128", prefix, &plen), 0);
    CHECK_EQ(plen, 128);
    generate_random_ipv6(prefix, plen, buf, sizeof(buf));
    CHECK(strcmp(buf, "2001:db8::1") == 0);

    // /0：任意地址都合法
    CHECK_EQ(parse_ipv6_prefix("::/0", prefix, &plen), 0);
    CHECK_EQ(plen, 0);
    ok = true;
    for (int i = 0; i < 100; ++i) {
        generate_random_ipv6(prefix, plen, buf, sizeof(buf));
        if (inet_pton(AF_INET6, buf, &a) != 1) { ok = false; break; }
    }
    CHECK(ok);

    // 错误分支
    unsigned char dummy[16];
    int dlen = 0;
    CHECK_EQ(parse_ipv6_prefix("2400:cb00:2049::", dummy, &dlen), -1);      // 缺前缀
    CHECK_EQ(parse_ipv6_prefix("2400:cb00:2049::/129", dummy, &dlen), -2);  // 越界
    CHECK_EQ(parse_ipv6_prefix("not-an-ipv6/48", dummy, &dlen), -3);        // 非法地址
}

// ---------------------------------------------------------------------------
// 4. TCP 测速核心
// ---------------------------------------------------------------------------
static void test_telnet_delay() {
    SECTION("test_telnet_delay");

    sock_t listen_fd = SOCK_INVALID;
    int port = 0;
    if (!listener_start(&listen_fd, &port)) {
        ++g_fail;
        printf("   [FAIL] 无法在回环地址上开启监听端口，后续用例跳过\n");
        return;
    }

    AcceptLoop loop;
    loop.start(listen_fd);

    // 连接一个真实在监听的本机端口：必须成功，且延迟合理
    double delay = -1.0;
    CHECK_EQ(test_telnet_delay("127.0.0.1", port, &delay), 0);
    CHECK(delay >= 0.0 && delay < 1000.0);

    // 连接一个没人监听的端口：必须失败，且不能崩溃
    // （可能立刻收到 RST，也可能被系统静默丢弃而在 1000ms 超时后返回，
    //   所以这里只要求“有测量值 + 没有崩”，不约束具体耗时）
    sock_t dead_fd = SOCK_INVALID;
    int dead_port = 0;
    CHECK(listener_start(&dead_fd, &dead_port));
    sock_close(dead_fd); // 立刻关掉，制造“连接被拒绝”
    delay = -1.0;
    int rc = test_telnet_delay("127.0.0.1", dead_port, &delay);
    printf("   连接无人监听的端口: 返回码 %d, 耗时 %.2f ms\n", rc, delay);
    CHECK(rc != 0);
    CHECK(delay >= 0.0);

    // 不存在的主机名：必须失败（多为 getaddrinfo 直接返回 -1），绝不能判成成功
    delay = 0.0;
    CHECK(test_telnet_delay("no-such-host.invalid.", 80, &delay) != 0);

    loop.finish();
    sock_close(listen_fd);
}

// ---------------------------------------------------------------------------
// 5. fd / socket 泄漏回归
//    第 1001 次成功连接后 fd 号就会 >= FD_SETSIZE(1024)，
//    未修复的版本会在 FD_SET 里触发 glibc abort。
// ---------------------------------------------------------------------------
static void test_fd_leak_regression() {
    SECTION("fd/socket 泄漏回归（1000+ 次成功连接）");

    sock_t listen_fd = SOCK_INVALID;
    int port = 0;
    if (!listener_start(&listen_fd, &port)) {
        ++g_fail;
        printf("   [FAIL] 无法开启监听端口\n");
        return;
    }

    AcceptLoop loop;
    loop.start(listen_fd);

#ifndef _WIN32
    int fds_before = count_open_fds();
#else
    int fds_before = -1;
#endif

    const int kRounds = 1200; // 故意超过 FD_SETSIZE(1024)
    bool all_ok = true;
    int failed_at = -1;
    for (int i = 0; i < kRounds; ++i) {
        double delay = 0.0;
        if (test_telnet_delay("127.0.0.1", port, &delay) != 0) {
            all_ok = false;
            failed_at = i;
            break;
        }
    }
    CHECK(all_ok);
    if (!all_ok) printf("   第 %d 次连接起开始失败\n", failed_at);

#ifndef _WIN32
    int fds_after = count_open_fds();
    printf("   打开的文件描述符: 连接前 %d, %d 次成功连接后 %d\n", fds_before, kRounds, fds_after);
    CHECK(fds_before > 0);
    CHECK(fds_after >= 0);
    CHECK(fds_after <= fds_before + 4); // 允许后台 accept 线程有 1 个瞬时 fd
#else
    printf("   Windows 上无 /proc/self/fd，仅校验 %d 次连接全部成功\n", kRounds);
#endif

    loop.finish();
    sock_close(listen_fd);
}

// ---------------------------------------------------------------------------
// 6. 端到端：栈式 IP 池 + 多线程 pop + CSV 输出
// ---------------------------------------------------------------------------
static void test_main_end_to_end() {
    SECTION("cidr_ping_main 端到端（栈式 IP 池）");

    sock_t listen_fd = SOCK_INVALID;
    int port = 0;
    if (!listener_start(&listen_fd, &port)) {
        ++g_fail;
        printf("   [FAIL] 无法开启监听端口\n");
        return;
    }

    AcceptLoop loop;
    loop.start(listen_fd);

    const int kTargets = 300;
    std::vector<std::string> args;
    args.push_back("cidr-ping");
    args.push_back("127.0.0.0/16");
    args.push_back(s_port(port));
    args.push_back("300");

    int rc = run_main(args);
    loop.finish();
    sock_close(listen_fd);

    CHECK_EQ(rc, 0);
    // 每个目标必须恰好产生一行：行数少于目标数说明 pop 丢元素，多于此说明重复出栈
    CHECK_EQ(count_csv_rows("rtts.csv"), kTargets);

    // 库模式（测试程序里没有定义 MAIN）不应写表头
    std::string first = first_csv_line("rtts.csv");
    printf("   CSV 首行: %s\n", first.c_str());
    CHECK(first.compare(0, 19, "ip,ip_with_brackets") != 0);
    // 127.0.0.0/16 前两段固定，形如 127.0.x.y
    CHECK(first.compare(0, 6, "127.0.") == 0);

    // IPv6 分支端到端（外网不可达也必须每个目标各写一行）
    std::vector<std::string> v6args;
    v6args.push_back("cidr-ping");
    v6args.push_back("2400:cb00:2049::/48");
    v6args.push_back("1");
    v6args.push_back("5");
    rc = run_main(v6args);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count_csv_rows("rtts.csv"), 5);
}

// ---------------------------------------------------------------------------
// 7. 参数校验：非法输入必须以非 0 退出
// ---------------------------------------------------------------------------
static void test_argument_validation() {
    SECTION("参数校验（返回码）");

    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.0/16", "0"}), 1);      // 端口 0
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.0/16", "65536"}), 1);  // 端口越界
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.0/16", "70000"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.0/16", "1", "0"}), 1); // 数量 0
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.0/16", "1", "-5"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "1.2.3/24", "1", "1"}), 1);     // 非法 IPv4
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "1.2.3.256/24", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "192.168.1.0/33", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "not-an-ipv6/48", "1", "1"}), 1); // 非法 IPv6
}

// ---------------------------------------------------------------------------
// 8. UDP 测速核心
// ---------------------------------------------------------------------------
static void test_udp_delay() {
    SECTION("test_udp_delay");

    UdpEchoServer echo;
    if (!echo.start()) {
        ++g_fail;
        printf("   [FAIL] 无法在回环地址上开启 UDP 回声服务，后续用例跳过\n");
        return;
    }

    unsigned char payload[4];
    memcpy(payload, "ping", 4);
    double delay = -1.0;

    // 有回声服务：必须成功，且延迟合理
    CHECK_EQ(test_udp_delay("127.0.0.1", echo.port, payload, sizeof(payload), &delay, NULL, RP_BUDGET_MS), RP_OK);
    CHECK(delay >= 0.0 && delay < 1000.0);

    // 默认的空数据报同样必须能完成一次往返
    delay = -1.0;
    CHECK_EQ(test_udp_delay("127.0.0.1", echo.port, kEmptyProbe, 0, &delay, NULL, RP_BUDGET_MS), RP_OK);
    CHECK(delay >= 0.0 && delay < 1000.0);

    // 回声服务确实收到了报文：证明 send() 真的把数据报发出去了
    CHECK(echo.recv_count.load() >= 2);

    // 无人监听的 UDP 端口：回环上 ICMP 端口不可达通常立刻回来（RP_UDP_ICMP）；
    // 个别平台会吞掉 ICMP 而表现为超时（RP_UDP_TIMEOUT）。
    // 两种都不是“成功”，所以这里只断言“不是成功 + 有测量值 + 不崩”。
    int dead_port = 0;
    CHECK(grab_closed_udp_port(&dead_port));
    delay = -1.0;
    int rc = test_udp_delay("127.0.0.1", dead_port, payload, sizeof(payload), &delay, NULL, RP_BUDGET_MS);
    printf("   UDP 打到无人监听的端口: 返回码 %d, 耗时 %.2f ms\n", rc, delay);
    CHECK(rc == RP_UDP_ICMP || rc == RP_UDP_TIMEOUT);
    CHECK(delay >= 0.0);

    // 不存在的主机名：绝不能判成成功
    delay = 0.0;
    CHECK(test_udp_delay("no-such-host.invalid.", 53, payload, sizeof(payload), &delay, NULL, RP_BUDGET_MS) != 0);

    // 分发函数：PROTO_UDP 必须走 UDP（回声服务在，所以必须成功）
    double d_udp = -1.0;
    CHECK_EQ(test_target_delay("127.0.0.1", echo.port, RP_PROTO_UDP, payload, sizeof(payload), &d_udp, NULL, RP_BUDGET_MS),
             RP_OK);
    CHECK(d_udp >= 0.0);

    echo.finish();
}

// ---------------------------------------------------------------------------
// 9. --tcp / --udp / --udp-payload / --help 参数解析
// ---------------------------------------------------------------------------
static void test_protocol_flags() {
    SECTION("--tcp / --udp 参数解析");

    UdpEchoServer echo;
    if (!echo.start()) {
        ++g_fail;
        printf("   [FAIL] 无法开启 UDP 回声服务\n");
        return;
    }

    // ① 不带任何协议开关 -> 默认 TCP：绝不能给 UDP 回声服务发报文
    int before = echo.recv_count.load();
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.1", s_port(echo.port), "1"}), 0);
    CHECK_EQ(echo.recv_count.load(), before);

    // ② 显式 --tcp：开关放在位置参数之后同样要生效
    before = echo.recv_count.load();
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "127.0.0.1", s_port(echo.port), "1", "--tcp"}),
             0);
    CHECK_EQ(echo.recv_count.load(), before);

    // ③ --udp：必须真的走 UDP，回声服务要收到报文
    before = echo.recv_count.load();
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp", "127.0.0.1", s_port(echo.port), "1"}),
             0);
    CHECK(echo.recv_count.load() > before);

    // ③b 分发函数：同一个端口上 TCP 与 UDP 的结果必须不同
    {
        unsigned char probe[1] = {0x41};
        double d_udp = -1.0;
        double d_tcp = -1.0;
        CHECK_EQ(test_target_delay("127.0.0.1", echo.port, RP_PROTO_UDP, probe, 1, &d_udp, NULL, RP_BUDGET_MS), RP_OK);
        CHECK(d_udp >= 0.0);
        // 该端口上只有 UDP 在监听，同一个端口走 TCP 必须失败
        CHECK(test_target_delay("127.0.0.1", echo.port, RP_PROTO_TCP, probe, 1, &d_tcp, NULL, RP_BUDGET_MS) != 0);
    }

    // ④ --udp-payload：合法的十六进制载荷要按字节发出去
    before = echo.recv_count.load();
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp",
                                               "--udp-payload=0x70,0x69,0x6e,0x67",
                                               "127.0.0.1", s_port(echo.port), "1"}),
             0);
    CHECK(echo.recv_count.load() > before);

    // ⑤ 网段模式 + --udp
    //    行数断言保证 IP 池被试空、每个目标都写了结果；
    //    收包数断言保证「每个 CIDR 生成的随机目标都真的发出了数据报」。
    //    这里不能断言“全部成功”：客户端 connect() 到 127.x.y.z 时，内核把源地址
    //    选成 127.0.0.1，回声服务于是把回包发到 127.0.0.1，而 connected socket 只
    //    接受来自对端 127.x.y.z 的报文，回包被过滤掉。Windows 与 Linux 行为一致，
    //    属于回环地址语义，与本工具的 UDP 实现无关。
    echo.recv_count.store(0);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp", "127.0.0.0/16",
                                               s_port(echo.port), "40"}),
             0);
    CHECK_EQ(count_csv_rows("rtts.csv"), 40);
    int received = echo.recv_count.load();
    printf("   127.0.0.0/16 段发送 40 个目标后，回声服务收到 %d 个数据报\n", received);
    CHECK(received >= 40);

    echo.finish();

    // ⑥ --help 返回 0；未知选项与非法载荷返回 1
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--help"}), 0);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--bogus"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-payload=zz", "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-payload=0a0", "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-payload=", "127.0.0.1", "1", "1"}), 1);
    // 旧写法（负数量）必须仍然走参数校验路径，而不是被当成未知开关
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp", "127.0.0.0/16", "1", "-5"}), 1);
}

// ---------------------------------------------------------------------------
// 10. WireGuard 原语 + 握手包组装
//
// 全部对着「独立实现」的产物比对，而不是自己跟自己对：
//   * BLAKE2s-256  -> RFC 7693 附录 B 的官方向量
//   * X25519       -> RFC 7748 §6.1 的 Alice/Bob 向量
//   * AEAD         -> python-cryptography 算出的向量（nonce 形状与 WireGuard 一致）
//   * 完整握手包   -> wgref.py（用 python-cryptography 独立实现同一套 Noise IKpsk2）
//                    生成的 148 字节确定性向量
// 只要握手包逐字节相同，就说明 HASH / HMAC / MAC / X25519 / AEAD 与组装顺序全都对。
// ---------------------------------------------------------------------------

// 十六进制（可含空白）-> 字节
static bool hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t n = 0;
    for (const char *p = hex; *p != '\0'; ++p) {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') continue;
        int hi = -1;
        if (*p >= '0' && *p <= '9') hi = *p - '0';
        else if (*p >= 'a' && *p <= 'f') hi = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') hi = *p - 'A' + 10;
        else return false;
        ++p;
        if (*p == '\0' || *p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') return false;
        int lo = -1;
        if (*p >= '0' && *p <= '9') lo = *p - '0';
        else if (*p >= 'a' && *p <= 'f') lo = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') lo = *p - 'A' + 10;
        else return false;
        if (n >= out_len) return false;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n == out_len;
}

// base64（标准或 URL-safe，允许省略 '='）-> 字节
static bool b64_to_bytes(const char *b64, unsigned char *out, size_t out_len) {
    static const char *TB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    int val = 0, bits = 0;
    for (const char *p = b64; *p != '\0'; ++p) {
        char c = *p;
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') break;
        const char *pos = strchr(TB, c);
        if (pos == NULL) {
            if (c == '-') pos = strchr(TB, '+');
            else if (c == '_') pos = strchr(TB, '/');
        }
        if (pos == NULL) return false;
        val = (val << 6) | (int)(pos - TB);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_len) return false;
            out[n++] = (unsigned char)((val >> bits) & 0xFF);
        }
    }
    return n == out_len;
}

static std::string bytes_to_hex(const unsigned char *p, size_t n) {
    static const char *D = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += D[p[i] >> 4];
        s += D[p[i] & 0x0F];
    }
    return s;
}

static void test_wireguard_primitives() {
    SECTION("WireGuard 原语（RFC 向量）");

    unsigned char out[64];

    // ---- BLAKE2s-256("abc")，RFC 7693 附录 B ----
    CHECK_EQ(wg_blake2s(out, 32, NULL, 0, (const unsigned char *)"abc", 3), (size_t)32);
    CHECK_STREQ(bytes_to_hex(out, 32),
             std::string("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));

    // ---- X25519，RFC 7748 §6.1 ----
    unsigned char a[32], bpub[32], shared[32];
    CHECK(hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32));
    CHECK(hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bpub, 32));
    CHECK(wg_x25519(shared, a, bpub));
    CHECK_STREQ(bytes_to_hex(shared, 32),
             std::string("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

    // 同一条私钥的 X25519 公钥
    wg_public_key(shared, a);
    CHECK_STREQ(bytes_to_hex(shared, 32),
             std::string("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));

    // ---- ChaCha20-Poly1305 AEAD，nonce = 00000000 || le64(counter) ----
    {
        unsigned char key[32], aad[12], pt[114], ct[130];
        CHECK(hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                           key, 32));
        CHECK(hex_to_bytes("50515253c0c1c2c3c4c5c6c7", aad, 12));
        const char *msg =
            "Ladies and Gentlemen of the class of '99: If I could offer you "
            "only one tip for the future, sunscreen would be it.";
        CHECK_EQ(strlen(msg), (size_t)114);
        memcpy(pt, msg, 114);

        CHECK(wg_aead_encrypt(ct, key, 0, pt, 114, aad, 12));
        CHECK_STREQ(bytes_to_hex(ct, 130),
                 std::string("663d7ec45b29ceaaa35505b8c1b3d94613a50fd7e315a748d35a378670746af8"
                             "67ab3404fe7b7655b904162b408190f3f8c781815bb8724e4ac22ea6351d3846"
                             "8cd370aa8ffb19e96edc915893cc6e1861c2af01ab0fb02df97ea145499bb87d"
                             "44ec7d738272327290570a03658b27b116665c21ea189f9450ff121509fd8142befc"));

        // 计数器落在 nonce 的后 8 字节，换个计数器结果必须变
        CHECK(wg_aead_encrypt(ct, key, 1, pt, 114, aad, 12));
        CHECK_STREQ(bytes_to_hex(ct, 130),
                 std::string("af7010641b0c07870c61fa51ef1af2867c2249b03f466826b4fc74ef71d8eebc"
                             "3d7d03d408fbc5a69c28a1f237a6be6387273db104002a892278305905a3c558"
                             "45adcffe878ddbe19d2115ab93a373ac405212f8baf098ce405cb46395c59b52"
                             "13cd6afa4dea5ed377ecb2bfa4cfdce9716109473dbdcf154e6e253e747918368410"));
    }
}

static void test_wireguard_handshake() {
    SECTION("WireGuard 握手发起包（确定性向量）");

    // 合成密钥，故意不是任何真实 WARP 账号的私钥
    unsigned char priv[32], peer[32], eph[32], reserved[3] = {0x11, 0x22, 0x33};
    CHECK(hex_to_bytes("000102030405060708090a0b0c0d0e0f"
                       "101112131415161718191a1b1c1d1e1f", priv, 32));
    CHECK(b64_to_bytes(WG_WARP_PEER_KEY_B64, peer, 32));
    for (int i = 0; i < 32; ++i) eph[i] = (unsigned char)(i + 1);

    // ① 公钥派生（由 python-cryptography 独立算出）
    unsigned char pub[32];
    wg_public_key(pub, priv);
    CHECK_STREQ(bytes_to_hex(pub, 32),
             std::string("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"));

    // ② 完整 148 字节握手包
    unsigned char pkt[WG_HANDSHAKE_LEN];
    CHECK(wg_build_handshake_initiation(pkt, priv, peer, reserved, eph, 1,
                                        1700000000000000000ULL));
    CHECK_STREQ(bytes_to_hex(pkt, WG_HANDSHAKE_LEN),
             std::string("011122330100000007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed"
                         "0bdfc0b2b86d1c7c13195e9131512235c10a32f2abc1cbd3c7869ac2a01f9461"
                         "19fba3aed4e5f9a16252677cd7eac6c891bc78c9f1b92b108187ecd8808cbd34"
                         "c5351dc757ab71d4b4919bde91e723fc883dd4339bdc5e06cc76ba081b71f95e"
                         "e32e919800000000000000000000000000000000"));

    // 报文结构：类型 / reserved / index / mac2
    CHECK_EQ((int)pkt[0], WG_MSG_HANDSHAKE_INITIATION);
    CHECK_EQ((int)pkt[1], 0x11);
    CHECK_EQ((int)pkt[2], 0x22);
    CHECK_EQ((int)pkt[3], 0x33);
    CHECK_EQ((int)pkt[4], 1); // sender_index 小端
    CHECK_EQ((int)pkt[5], 0);
    CHECK_EQ((int)pkt[6], 0);
    CHECK_EQ((int)pkt[7], 0);
    for (int i = 132; i < 148; ++i) {
        CHECK_EQ((int)pkt[i], 0); // mac2 必须全零
    }

    // ③ 换时间戳 / 换 reserved / 换 index，包必须跟着变（说明这些字段真的参与运算）
    {
        unsigned char p2[WG_HANDSHAKE_LEN];
        CHECK(wg_build_handshake_initiation(p2, priv, peer, reserved, eph, 1,
                                            1700000001000000000ULL));
        CHECK(memcmp(p2, pkt, WG_HANDSHAKE_LEN) != 0);

        CHECK(wg_build_handshake_initiation(p2, priv, peer, reserved, eph, 2,
                                            1700000000000000000ULL));
        // sender_index 不参与 Noise 运算（它是明文头字段），所以第 8~115 字节的
        // ephemeral / encrypted_static / encrypted_timestamp 完全一致……
        CHECK(memcmp(p2 + 8, pkt + 8, 108) == 0);
        // ……但 mac1 覆盖了 index，所以第 116~131 字节必然不同
        CHECK(memcmp(p2 + 116, pkt + 116, 16) != 0);
        // mac2 两边都是 0
        CHECK(memcmp(p2 + 132, pkt + 132, 16) == 0);

        unsigned char r2[3] = {0, 0, 0};
        CHECK(wg_build_handshake_initiation(p2, priv, peer, r2, eph, 1,
                                            1700000000000000000ULL));
        CHECK(memcmp(p2, pkt, 148) != 0);
    }

    // ④ 参数为 NULL 时必须失败而不是崩
    CHECK(!wg_build_handshake_initiation(NULL, priv, peer, reserved, eph, 1, 0));
    CHECK(!wg_build_handshake_initiation(pkt, NULL, peer, reserved, eph, 1, 0));
    CHECK(!wg_build_handshake_initiation(pkt, priv, NULL, reserved, eph, 1, 0));
    CHECK(!wg_build_handshake_initiation(pkt, priv, peer, NULL, eph, 1, 0));
    CHECK(!wg_build_handshake_initiation(pkt, priv, peer, reserved, NULL, 1, 0));

    // ⑤ blake2s 的入参校验
    CHECK_EQ(wg_blake2s(pkt, 0, NULL, 0, (const unsigned char *)"x", 1), (size_t)0);
    CHECK_EQ(wg_blake2s(pkt, 33, NULL, 0, (const unsigned char *)"x", 1), (size_t)0);
    CHECK_EQ(wg_blake2s(pkt, 32, NULL, 33, (const unsigned char *)"x", 1), (size_t)0);
}

// ---------------------------------------------------------------------------
// 11. --wg / --wg-key / --wg-reserved / --full 参数解析与协议分发
// ---------------------------------------------------------------------------
static void test_wg_protocol_flags() {
    SECTION("--wg / --full 参数解析");

    // 一个不会被当成真实 WARP 私钥的合成密钥（32 字节 0..31）
    const std::string KEY_HEX =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const std::string KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const std::string KEY_ARG = "--wg-key=" + KEY_B64;

    // ① --wg 缺私钥 -> 直接报错退出，不能带着一把空密钥去打网络
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", "127.0.0.1", "1", "1"}), 1);
    // ② 私钥格式非法
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", "--wg-key=zzz",
                                               "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", "--wg-key=AAECAw",
                                               "127.0.0.1", "1", "1"}), 1);
    // ③ reserved 格式非法
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG,
                                               "--wg-reserved=zz", "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG,
                                               "--wg-reserved=01020304", "127.0.0.1", "1", "1"}), 1);
    // ④ --udp-timeout 非法
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-timeout=abc",
                                               "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-timeout=0",
                                               "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-timeout=-5",
                                               "127.0.0.1", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--udp-timeout=99999",
                                               "127.0.0.1", "1", "1"}), 1);

    // ⑤ 回声服务把回包首字节设成 0x02，模拟真实握手响应
    UdpEchoServer echo;
    if (!echo.start()) {
        ++g_fail;
        printf("   [FAIL] 无法开启 UDP 回声服务\n");
        return;
    }
    echo.reply_first.store(WG_MSG_HANDSHAKE_RESPONSE);

    // 分发函数：PROTO_WG 走 UDP 传输，并且要把回包首字节带回来
    {
        unsigned char pkt[WG_HANDSHAKE_LEN];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = WG_MSG_HANDSHAKE_INITIATION; // 假装是握手发起包
        double ms = -1.0;
        unsigned char rt = 0;
        echo.recv_count.store(0);
        CHECK_EQ(test_target_delay("127.0.0.1", echo.port, RP_PROTO_WG, pkt,
                                   sizeof(pkt), &ms, &rt, RP_BUDGET_MS), RP_OK);
        CHECK(ms >= 0.0 && ms < 1000.0);
        CHECK_EQ((int)rt, WG_MSG_HANDSHAKE_RESPONSE); // resp_type 真的被填了
        CHECK_EQ(echo.last_len.load(), (int)WG_HANDSHAKE_LEN);
        CHECK_EQ(echo.last_first.load(), WG_MSG_HANDSHAKE_INITIATION);
    }

    // ⑥ 走一遍完整入口：必须在网线上发出 148 字节握手包
    {
        echo.recv_count.store(0);
        CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG,
                                                   "127.0.0.1", s_port(echo.port), "1"}), 0);
        CHECK_EQ(echo.recv_count.load(), 1);
        CHECK_EQ(echo.last_len.load(), (int)WG_HANDSHAKE_LEN);
        CHECK_EQ(echo.last_first.load(), WG_MSG_HANDSHAKE_INITIATION);
        CHECK_EQ(count_csv_rows("rtts.csv"), 1);
        std::string line = first_csv_line("rtts.csv");
        printf("   --wg 端到端 CSV: %s\n", line.c_str());
        CHECK(line.find("WG") != std::string::npos);
        CHECK(line.find("0x02") != std::string::npos);
    }

    // ⑦ --wg-reserved=010203 要真的出现在报文第 1~3 字节
    {
        echo.recv_count.store(0);
        echo.last_head64.store(0);
        CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG,
                                                   "--wg-reserved=010203",
                                                   "127.0.0.1", s_port(echo.port), "1"}), 0);
        CHECK_EQ(echo.last_first.load(), WG_MSG_HANDSHAKE_INITIATION);
        CHECK_EQ(echo.last_len.load(), (int)WG_HANDSHAKE_LEN);
        unsigned long long h = echo.last_head64.load();
        CHECK_EQ((int)((h >> 0) & 0xFF), WG_MSG_HANDSHAKE_INITIATION);
        CHECK_EQ((int)((h >> 8) & 0xFF), 0x01);   // reserved[0]
        CHECK_EQ((int)((h >> 16) & 0xFF), 0x02);  // reserved[1]
        CHECK_EQ((int)((h >> 24) & 0xFF), 0x03);  // reserved[2]
    }

    // ⑦b 默认 reserved 必须是 000000（WARP 握手硬性要求）
    {
        echo.recv_count.store(0);
        echo.last_head64.store(0);
        CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG,
                                                   "127.0.0.1", s_port(echo.port), "1"}), 0);
        unsigned long long h = echo.last_head64.load();
        CHECK_EQ((int)((h >> 8) & 0xFF), 0);
        CHECK_EQ((int)((h >> 16) & 0xFF), 0);
        CHECK_EQ((int)((h >> 24) & 0xFF), 0);
    }

    // ⑧ --wg 之后又给 --tcp：最后一次生效，绝不能往回声服务发 UDP
    {
        int before = echo.recv_count.load();
        CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", KEY_ARG, "--tcp",
                                                   "127.0.0.1", s_port(echo.port), "1"}), 0);
        CHECK_EQ(echo.recv_count.load(), before);
    }

    // ⑨ --wg 没给端口时默认 2408（本地没人监听，只会超时/收到 ICMP，但端口必须写对）
    {
        std::vector<std::string> a;
        a.push_back("cidr-ping");
        a.push_back("--wg");
        a.push_back(KEY_ARG);
        a.push_back("--udp-timeout=200"); // 缩短等待，别让测试卡住
        a.push_back("127.0.0.1");         // 只给主机：端口与数量都走默认值
        CHECK_EQ(run_main(a), 0);
        std::string line = first_csv_line("rtts.csv");
        printf("   --wg 默认端口 CSV: %s\n", line.c_str());
        CHECK(line.find(":2408") != std::string::npos);
    }

    echo.finish();

    // ⑩ --full：整段枚举，目标数由前缀长度决定
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "127.0.0.0/30",
                                               "1", "1"}), 0);
    CHECK_EQ(count_csv_rows("rtts.csv"), 4); // /30 = 4 个地址
    {
        // 多线程写 CSV 的顺序不确定，只能断言「四个地址都出现了」
        static const char *WANT[4] = {"127.0.0.0,", "127.0.0.1,", "127.0.0.2,", "127.0.0.3,"};
        for (int i = 0; i < 4; ++i) {
            CHECK(csv_contains("rtts.csv", WANT[i]));
        }
    }

    // --full 对 IPv6 同样生效（/126 = 4 个地址）
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "2400:cb00:2049::/126",
                                               "1", "1"}), 0);
    CHECK_EQ(count_csv_rows("rtts.csv"), 4);

    // 网段太大必须拒绝，而不是老老实实循环 40 亿次
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "0.0.0.0/0", "1", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "10.0.0.0/8", "1", "1"}), 1);
    // IPv6 太短也拒绝
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "2400:cb00::/64", "1", "1"}), 1);

    // --full 时不再校验「生成IP数量」，但仍要拦住非法端口
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "127.0.0.0/30", "0", "1"}), 1);
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--full", "127.0.0.0/30",
                                               "1", "0"}), 0);

    // 私钥两种写法必须等价（64 位十六进制 vs base64）
    CHECK_EQ(run_main(std::vector<std::string>{"cidr-ping", "--wg", "--wg-key=" + KEY_HEX,
                                               "--udp-timeout=200", "127.0.0.1", "1", "1"}), 0);
    CHECK_EQ(count_csv_rows("rtts.csv"), 1);
}

// ---------------------------------------------------------------------------
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("cidr-ping 测试套件\n");
    printf("工作目录下的 rtts.csv 会被反复覆盖，这是预期行为\n");

    test_parse_ipv4_prefix();
    test_generate_random_ipv4();
    test_ipv6();
    test_telnet_delay();
    test_udp_delay();
    test_fd_leak_regression();
    test_main_end_to_end();
    test_argument_validation();
    test_protocol_flags();
    test_wireguard_primitives();
    test_wireguard_handshake();
    test_wg_protocol_flags();

    printf("\n----------------------------------------\n");
    printf("通过: %d, 失败: %d\n", g_pass, g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
