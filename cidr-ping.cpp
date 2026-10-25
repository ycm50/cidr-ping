// cidr-ping.cpp —— 并行网段延迟测速（TCP / UDP / WireGuard）
//
// 设计要点（改动过的关键约定）：
//   * 所有命令行数值都走 text-util.h 的严格解析：整串必须完整消费、必须在范围内。
//   * 每个目标（含 DNS 解析与全部地址尝试）共享一个「总等待预算」，用单调时钟计时。
//   * 随机数：临时私钥 / sender_index 用系统密码学随机源（POSIX /dev/urandom、
//     Windows BCryptGenRandom），拿不到就直接报错退出，绝不退化到 rand()。
//   * WireGuard 回包必须通过「类型 + 长度 + 保留字段」结构校验才被当作 WG 报文。
//   * 采样使用 splitmix64 且在小网段内不重复取地址；随机私钥不回显公钥。
//   * CSV 字段一律经 csv_escape() 转义，并新增第 5 列 detail 记录系统错误信息。

#include "cidr-ping.h"
#include "wireguard.h"
#include "text-util.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <stack>
#include <string>
#include <functional> // std::ref —— libc++ 的 <thread> 不会间接包含它（llvm-mingw / bionic）
#include <cctype>     // std::isxdigit / std::tolower
#include <chrono>
#include <cstdint>    // uintptr_t
#include <cstdarg>    // va_list（set_diag）
#include <cstdio>     // snprintf / fprintf
#include <unordered_set>

#ifndef _WIN32
#include <fcntl.h>      // fcntl(), O_NONBLOCK
#include <sys/select.h> // select(), fd_set
#endif

// ===== 测试方式 =====
enum TestProtocol {
    PROTO_TCP = 0, // 默认：非阻塞 connect() 三次握手
    PROTO_UDP = 1, // 发一个 UDP 数据报并等回包
    PROTO_WG  = 2  // 发一个 WireGuard 握手发起包，等握手响应
};

// UDP/WG 三次发送的等待预算按比例切分：0.5 + 0.3 + 0.2 = 1
static const double UDP_SLICE_FRACTION[3] = {0.5, 0.3, 0.2};
#define UDP_ATTEMPTS 3
#define UDP_TIMEOUT_MS 1000.0  // --udp-timeout 的默认值
#define WG_DEFAULT_PORT 2408
// 一次运行最多生成的目标数。上限既防内存爆炸，也让「不重复抽样」的
// 哈希表开销保持在可接受范围内。
#define MAX_TARGETS 262144ULL

// 默认载荷：空数据报。
static const unsigned char kEmptyUdpPayload[1] = {0};

// 前置声明：UDP 接收路径要用它做 WireGuard 报文结构校验
static bool wg_response_structurally_valid(const unsigned char *data, int len, unsigned char *type_out);

// ===========================================================================
// 平台小工具：单调时钟 / 睡眠 / 密码学随机数 / 错误信息
// ===========================================================================

#ifdef _WIN32

// 系统密码学随机源：运行时从 bcrypt.dll 取 BCryptGenRandom。
// 这样不依赖 bcrypt.h / libbcrypt.a，避免 llvm-mingw、MSVC、MinGW 在
// 头文件与导入库上的差异（Windows Vista+ 一定带 bcrypt.dll）。
typedef long (WINAPI *CpBCryptGenRandomFn)(void *hAlgorithm, unsigned char *pbBuffer,
                                           unsigned long cbBuffer, unsigned long dwFlags);
#define CP_BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002UL

static double monotonic_ms() {
    static LARGE_INTEGER freq;
    static bool freq_init = false;
    if (!freq_init) {
        QueryPerformanceFrequency(&freq);
        freq_init = true;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / (double)freq.QuadPart;
}

static bool crypto_random_bytes(unsigned char *out, size_t n) {
    if (n == 0) return true;
    if (out == NULL) return false;

    HMODULE lib = LoadLibraryA("bcrypt.dll");
    if (lib == NULL) return false;

    CpBCryptGenRandomFn fn =
        (CpBCryptGenRandomFn)(void *)GetProcAddress(lib, "BCryptGenRandom");
    bool ok = (fn != NULL) &&
              (fn(NULL, out, (unsigned long)n, CP_BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);

    FreeLibrary(lib);
    return ok;
}

static std::string os_error_detail(int code) {
    switch (code) {
        case WSAECONNREFUSED: return "连接被对方拒绝(10061)";
        case WSAETIMEDOUT:    return "连接超时(10060)";
        case WSAEHOSTUNREACH: return "主机不可达(10065)";
        case WSAENETUNREACH:  return "网络不可达(10051)";
        case WSAHOST_NOT_FOUND: return "主机不存在(11001)";
        default: break;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "系统错误码 %d", code);
    return std::string(buf);
}

static std::string gai_error_detail(int code) {
    char buf[96];
    snprintf(buf, sizeof(buf), "getaddrinfo 错误码 %d", code);
    return std::string(buf);
}

void set_console_utf8() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

#else // POSIX

#include <cstdio>

static double monotonic_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

// POSIX：/dev/urandom 在 Linux / Android(Termux) / macOS / BSD 上都有。
// 拿不到就返回 false，由调用方决定「报错退出」而不是退化到弱随机。
static bool crypto_random_bytes(unsigned char *out, size_t n) {
    if (n == 0) return true;
    if (out == NULL) return false;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;

    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (r == 0) break;
        got += (size_t)r;
    }
    close(fd);
    return got == n;
}

static std::string os_error_detail(int code) {
    char buf[160];
    snprintf(buf, sizeof(buf), "%s (errno %d)", strerror(code), code);
    return std::string(buf);
}

static std::string gai_error_detail(int code) {
    const char *s = gai_strerror(code);
    char buf[192];
    snprintf(buf, sizeof(buf), "%s (getaddrinfo %d)", (s != NULL) ? s : "未知错误", code);
    return std::string(buf);
}

void set_console_utf8() {
    // Not needed for POSIX systems
}

#endif

// ===========================================================================
// 采样用 PRNG（splitmix64）—— 只用于选地址，不用于任何密码学用途
// ===========================================================================

static std::atomic<unsigned long long> g_prng_state(0);
static std::atomic<bool> g_prng_seeded(false);

static unsigned long long splitmix64(unsigned long long &x) {
    unsigned long long z = (x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void seed_prng() {
    unsigned long long seed = 0;
    unsigned char buf[8];
    if (crypto_random_bytes(buf, sizeof(buf))) {
        for (size_t i = 0; i < sizeof(buf); ++i) seed |= (unsigned long long)buf[i] << (8 * i);
    } else {
        // 采样随机性不涉及安全，退化成时间 + 栈地址混合也可以接受
        seed = (unsigned long long)time(NULL) * 1000000007ULL;
        seed ^= (unsigned long long)(uintptr_t)&g_prng_state;
        seed ^= (unsigned long long)monotonic_ms() * 1000003ULL;
    }
    g_prng_state.store(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed);
    g_prng_seeded.store(true);
}

static unsigned long long rng_u64() {
    if (!g_prng_seeded.load()) seed_prng();
    unsigned long long x = g_prng_state.load();
    unsigned long long v = splitmix64(x);
    g_prng_state.store(x);
    return v;
}

// 把采样到的「网段内偏移」写进输出（IPv4 用）
static unsigned int rng_below_32(unsigned int bound) { // bound > 0
    return (unsigned int)(rng_u64() % (unsigned long long)bound);
}

static unsigned long long rng_below_64(unsigned long long bound) { // bound > 0
    return rng_u64() % bound;
}

// ===========================================================================
// TCP 测速：非阻塞 connect + select，整个目标共享一个总预算
// ===========================================================================

int test_telnet_delay(const char *hostname, int port, double *delay_ms) {
    return test_target_delay(hostname, port, PROTO_TCP, NULL, 0, delay_ms, NULL,
                             CP_DEFAULT_CONNECT_TIMEOUT_MS);
}

// 供内部复用：返回状态码，把「系统错误」写进出参 err
static int tcp_connect_with_budget(const char *hostname, int port, double *delay_ms,
                                   double budget_ms, std::string &err) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return CP_ERR_WINSOCK;
#else
    (void)0;
#endif

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    // 计时从 DNS 解析之前开始，所以预算真的覆盖「解析 + 全部地址尝试」
    const double start = monotonic_ms();

    int gai = getaddrinfo(hostname, port_str, &hints, &result);
    if (gai != 0) {
        err = gai_error_detail(gai);
#ifdef _WIN32
        WSACleanup();
#endif
        *delay_ms = monotonic_ms() - start;
        return CP_ERR_RESOLVE;
    }

    int final_rc = CP_ERR_NO_ADDR;
    bool saw_addr = false;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        saw_addr = true;

        double used = monotonic_ms() - start;
        double remaining = budget_ms - used;
        if (remaining <= 0.0) {
            err = "总预算内未完成 TCP 握手";
            final_rc = CP_ERR_TIMEOUT;
            break;
        }

#ifdef _WIN32
        SOCKET sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) { final_rc = CP_ERR_SOCKET; continue; }
        u_long nonblock = 1;
        ioctlsocket(sockfd, FIONBIO, &nonblock);
#else
        int sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd < 0) { final_rc = CP_ERR_SOCKET; continue; }
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            *delay_ms = monotonic_ms() - start;
#ifdef _WIN32
            closesocket(sockfd);
            freeaddrinfo(result);
            WSACleanup();
#else
            close(sockfd);
            freeaddrinfo(result);
#endif
            return CP_OK;
        }

#ifdef _WIN32
        int connect_err = WSAGetLastError();
        bool in_progress = (connect_err == WSAEWOULDBLOCK || connect_err == WSAEINPROGRESS);
#else
        int connect_err = errno;
        bool in_progress = (connect_err == EINPROGRESS);
#endif

        if (!in_progress) {
            err = os_error_detail(connect_err);
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            final_rc = CP_ERR_CONNECT;
            continue;
        }

        // 等待剩余预算（而不是固定的 1000ms）
        used = monotonic_ms() - start;
        remaining = budget_ms - used;
        if (remaining <= 0.0) {
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            err = "总预算内未完成 TCP 握手";
            final_rc = CP_ERR_TIMEOUT;
            break;
        }

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv;
        tv.tv_sec = (long)(remaining / 1000.0);
        tv.tv_usec = (long)((remaining - (double)tv.tv_sec * 1000.0) * 1000.0);
        if (tv.tv_sec == 0 && tv.tv_usec <= 0) tv.tv_usec = 1000;

#ifdef _WIN32
        int sel_ret = select((int)sockfd + 1, NULL, &wfds, NULL, &tv);
#else
        int sel_ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
#endif

        if (sel_ret == 0) {
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            err = "总预算内未完成 TCP 握手";
            final_rc = CP_ERR_TIMEOUT;
            break; // 总预算耗尽：不再尝试后续地址
        }
        if (sel_ret < 0) {
#ifdef _WIN32
            err = os_error_detail(WSAGetLastError());
            closesocket(sockfd);
#else
            err = os_error_detail(errno);
            close(sockfd);
#endif
            final_rc = CP_ERR_CONNECT;
            continue;
        }

        int so_error = 0;
#ifdef _WIN32
        int len = sizeof(so_error);
        int opt_rc = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
#else
        socklen_t len = sizeof(so_error);
        int opt_rc = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
#endif

        if (opt_rc != 0 || so_error != 0) {
            // 真正的失败码是 SO_ERROR 的内容；此时 errno 可能已被 getsockopt 覆盖，
            // 只有 getsockopt 本身失败才退回 errno / WSAGetLastError（且只取一次，
            // 重复调用 WSAGetLastError 可能读到被覆盖后的值）。
            int detail_code = so_error;
            if (opt_rc != 0) {
#ifdef _WIN32
                int wsa = WSAGetLastError();
                detail_code = (wsa != 0) ? wsa : so_error;
#else
                detail_code = (errno != 0) ? errno : so_error;
#endif
            }
            err = os_error_detail(detail_code);
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            final_rc = CP_ERR_CONNECT;
            continue;
        }

        *delay_ms = monotonic_ms() - start;
#ifdef _WIN32
        closesocket(sockfd);
        freeaddrinfo(result);
        WSACleanup();
#else
        close(sockfd);
        freeaddrinfo(result);
#endif
        return CP_OK;
    }

    *delay_ms = monotonic_ms() - start;
#ifdef _WIN32
    WSACleanup();
#else
    (void)0;
#endif
    freeaddrinfo(result);
    if (!saw_addr) return CP_ERR_NO_ADDR;
    return final_rc;
}

// ===========================================================================
// UDP / WireGuard 测速：connect() 固定目标 → 按预算补发 → select() 等回包
// ===========================================================================

static int udp_roundtrip_with_budget(const char *hostname, int port,
                                     const unsigned char *payload, size_t payload_len,
                                     double *delay_ms, unsigned char *resp_type,
                                     double budget_ms, bool validate_wg,
                                     std::string &err) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return CP_ERR_WINSOCK;
#else
    (void)0;
#endif

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    // 计时覆盖 DNS + 全部补发，真正做到「总预算」
    const double start = monotonic_ms();

    int gai = getaddrinfo(hostname, port_str, &hints, &result);
    if (gai != 0) {
        err = gai_error_detail(gai);
#ifdef _WIN32
        WSACleanup();
#endif
        *delay_ms = monotonic_ms() - start;
        return CP_ERR_RESOLVE;
    }

    int final_rc = CP_ERR_NO_ADDR;
    bool saw_addr = false;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        saw_addr = true;

#ifdef _WIN32
        SOCKET sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) { final_rc = CP_ERR_SOCKET; continue; }
        u_long nonblock = 1;
        ioctlsocket(sockfd, FIONBIO, &nonblock);
#else
        int sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd < 0) { final_rc = CP_ERR_SOCKET; continue; }
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif

        // connect() 对 UDP 不产生流量，只是固定目标：之后 ICMP 差错才会回传给 recv()
        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) != 0) {
#ifdef _WIN32
            err = os_error_detail(WSAGetLastError());
            closesocket(sockfd);
#else
            err = os_error_detail(errno);
            close(sockfd);
#endif
            final_rc = CP_ERR_CONNECT;
            continue;
        }

        final_rc = CP_ERR_UDP_TIMEOUT;

        for (int attempt = 0; attempt < UDP_ATTEMPTS; ++attempt) {
            double remaining = budget_ms - (monotonic_ms() - start);
            if (remaining <= 0.0) break; // 总预算用完

            double slice = budget_ms * UDP_SLICE_FRACTION[attempt];
            if (slice > remaining) slice = remaining;

            int send_rc;
#ifdef _WIN32
            send_rc = send(sockfd, (const char *)payload, (int)payload_len, 0);
            if (send_rc == SOCKET_ERROR) {
                err = os_error_detail(WSAGetLastError());
                final_rc = CP_ERR_CONNECT;
                break;
            }
#else
            send_rc = (int)send(sockfd, payload, payload_len, 0);
            if (send_rc < 0) {
                err = os_error_detail(errno);
                final_rc = CP_ERR_CONNECT;
                break;
            }
#endif

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec = (long)(slice / 1000.0);
            tv.tv_usec = (long)((slice - (double)tv.tv_sec * 1000.0) * 1000.0);
            if (tv.tv_sec == 0 && tv.tv_usec <= 0) tv.tv_usec = 1000;

#ifdef _WIN32
            int sel_ret = select((int)sockfd + 1, &rfds, NULL, NULL, &tv);
#else
            int sel_ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
            if (sel_ret < 0) {
#ifdef _WIN32
                err = os_error_detail(WSAGetLastError());
#else
                err = os_error_detail(errno);
#endif
                final_rc = CP_ERR_CONNECT;
                break;
            }
            if (sel_ret == 0) continue; // 本轮没等到，下一轮补发

            char buf[2048];
#ifdef _WIN32
            int n = recv(sockfd, buf, sizeof(buf), 0);
#else
            ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
#endif
            if (n >= 0) {
                unsigned char resp_byte = (n >= 1) ? (unsigned char)buf[0] : 0;

                // WireGuard 模式：只有通过「类型 + 长度 + 保留字段」校验的回包才算数。
                // 否则它不是 WireGuard 报文（或不是本次握手），继续在预算内等下一个包。
                if (validate_wg) {
                    unsigned char wg_type = 0;
                    if (!wg_response_structurally_valid((const unsigned char *)buf, (int)n, &wg_type)) {
                        err = "收到非 WireGuard 报文，已忽略并继续等待";
                        final_rc = CP_ERR_WG_NOT_WG;
                        if (resp_type != NULL) *resp_type = resp_byte;
                        continue;
                    }
                    resp_byte = wg_type;
                }

                if (resp_type != NULL) *resp_type = resp_byte;
                err.clear(); // 成功时不要把「之前忽略过的无效报文」当成诊断信息带出去
                *delay_ms = monotonic_ms() - start;
#ifdef _WIN32
                closesocket(sockfd);
                freeaddrinfo(result);
                WSACleanup();
#else
                close(sockfd);
                freeaddrinfo(result);
#endif
                return CP_OK;
            }

#ifdef _WIN32
            int recv_err = WSAGetLastError();
            if (recv_err == WSAEWOULDBLOCK) continue;
            if (recv_err == WSAECONNRESET) { // ICMP 端口不可达
                *delay_ms = monotonic_ms() - start;
                closesocket(sockfd);
                freeaddrinfo(result);
                WSACleanup();
                return CP_ERR_UDP_ICMP;
            }
            err = os_error_detail(recv_err);
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            if (errno == ECONNREFUSED) { // ICMP 端口不可达
                *delay_ms = monotonic_ms() - start;
                close(sockfd);
                freeaddrinfo(result);
                return CP_ERR_UDP_ICMP;
            }
            err = os_error_detail(errno);
#endif
            final_rc = CP_ERR_CONNECT;
            break;
        }

        (void)0;
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        if (final_rc == CP_ERR_UDP_TIMEOUT) break; // 超时：与 TCP 版一致，不再试下一个地址
    }

    *delay_ms = monotonic_ms() - start;
#ifdef _WIN32
    WSACleanup();
#endif
    freeaddrinfo(result);
    if (!saw_addr) return CP_ERR_NO_ADDR;
    if (final_rc == CP_ERR_UDP_TIMEOUT && err.empty()) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%.0f ms 预算内未收到任何回包（已按 %d 轮补发）",
                 budget_ms, UDP_ATTEMPTS);
        err = buf;
    }
    return final_rc;
}

int test_udp_delay(const char *hostname, int port,
                   const unsigned char *payload, size_t payload_len,
                   double *delay_ms, unsigned char *resp_type,
                   double budget_ms) {
    std::string err;
    return udp_roundtrip_with_budget(hostname, port, payload, payload_len,
                                     delay_ms, resp_type, budget_ms, false, err);
}

// 内部实现：把失败原因通过 *err_out 显式返回（不再用 thread_local 隐式状态，
// 这样在 llvm-mingw / bionic 的静态链接下也没有额外运行时依赖）。
static int test_target_delay_impl(const char *hostname, int port, int protocol,
                                  const unsigned char *udp_payload, size_t udp_payload_len,
                                  double *delay_ms, unsigned char *resp_type,
                                  double budget_ms, std::string *err_out) {
    std::string err;

    int rc;
    if (protocol == PROTO_UDP || protocol == PROTO_WG) {
        rc = udp_roundtrip_with_budget(hostname, port, udp_payload, udp_payload_len,
                                       delay_ms, resp_type, budget_ms,
                                       protocol == PROTO_WG, err);
    } else {
        rc = tcp_connect_with_budget(hostname, port, delay_ms, budget_ms, err);
    }

    if (err_out != NULL) *err_out = err;
    return rc;
}

int test_target_delay(const char *hostname, int port, int protocol,
                      const unsigned char *udp_payload, size_t udp_payload_len,
                      double *delay_ms, unsigned char *resp_type,
                      double budget_ms) {
    return test_target_delay_impl(hostname, port, protocol, udp_payload, udp_payload_len,
                                  delay_ms, resp_type, budget_ms, NULL);
}

// ===========================================================================
// WireGuard 回包结构校验 —— 「首字节是 2」不等于「这是 WireGuard 服务端」
// ===========================================================================

// 各类型报文的固定/最小长度（WireGuard 协议定义）
//   1 handshake initiation : 148
//   2 handshake response   : 92
//   3 cookie reply         : 64
//   4 transport data       : >= 32（16 字节头 + 至少 16 字节 AEAD tag）
static bool wg_response_structurally_valid(const unsigned char *data, int len, unsigned char *type_out) {
    if (data == NULL || len < 4) return false;

    unsigned char t = data[0];
    // 类型 2/3/4 的保留字段必须是 0（WireGuard 规范）
    bool reserved_ok = (data[1] == 0 && data[2] == 0 && data[3] == 0);

    switch (t) {
        case WG_MSG_HANDSHAKE_INITIATION:
            if (len != WG_HANDSHAKE_LEN) return false;
            break;
        case WG_MSG_HANDSHAKE_RESPONSE:
            if (len != 92 || !reserved_ok) return false;
            break;
        case WG_MSG_COOKIE_REPLY:
            if (len != 64 || !reserved_ok) return false;
            break;
        case WG_MSG_TRANSPORT_DATA:
            if (len < 32 || !reserved_ok) return false;
            break;
        default:
            return false;
    }

    if (type_out != NULL) *type_out = t;
    return true;
}

// ===========================================================================
// 目标格式化 / 状态文本（导出给 multy_apply 等复用）
// ===========================================================================

void cp_format_target(const char *target, int port,
                      char *host_out, size_t host_size,
                      char *hostport_out, size_t hostport_size) {
    const char *t = (target != NULL) ? target : "";

    // 只有「确实是 IPv6 字面量」才加方括号；主机名不会因为含 ':' 被误判
    bool is_v6_literal = false;
#ifdef _WIN32
    struct in6_addr tmp6;
    if (inet_pton(AF_INET6, t, &tmp6) == 1) is_v6_literal = true;
#else
    struct in6_addr tmp6;
    if (inet_pton(AF_INET6, t, &tmp6) == 1) is_v6_literal = true;
#endif

    if (host_out != NULL && host_size > 0) {
        if (is_v6_literal) snprintf(host_out, host_size, "[%s]", t);
        else              snprintf(host_out, host_size, "%s", t);
    }
    if (hostport_out != NULL && hostport_size > 0) {
        if (is_v6_literal) snprintf(hostport_out, hostport_size, "[%s]:%d", t, port);
        else               snprintf(hostport_out, hostport_size, "%s:%d", t, port);
    }
}

void cp_status_text(int protocol, int result, int resp_type,
                    char *status, size_t status_size,
                    char *detail, size_t detail_size) {
    if (status != NULL && status_size > 0) status[0] = '\0';
    if (detail != NULL && detail_size > 0) detail[0] = '\0';
    if (status == NULL || status_size == 0) return;

    const bool is_wg = (protocol == PROTO_WG);
    const bool is_udp = (protocol == PROTO_UDP);

    switch (result) {
        case CP_OK:
            if (is_wg) {
                switch ((unsigned char)resp_type) {
                    case WG_MSG_HANDSHAKE_RESPONSE:
                        snprintf(status, status_size, "WG握手响应(0x02)");
                        break;
                    case WG_MSG_COOKIE_REPLY:
                        snprintf(status, status_size, "WGCookie回复(0x03)");
                        break;
                    case WG_MSG_HANDSHAKE_INITIATION:
                        snprintf(status, status_size, "WG握手发起(0x01)");
                        break;
                    case WG_MSG_TRANSPORT_DATA:
                        snprintf(status, status_size, "WG传输数据(0x04)");
                        break;
                    default:
                        snprintf(status, status_size, "WG未知报文(0x%02x)", (unsigned)resp_type & 0xFF);
                        if (detail != NULL && detail_size > 0) {
                            snprintf(detail, detail_size, "回包首字节 0x%02x", (unsigned)resp_type & 0xFF);
                        }
                        break;
                }
            } else {
                snprintf(status, status_size, "成功");
            }
            break;

        case CP_ERR_RESOLVE:
            snprintf(status, status_size, "无法解析主机名");
            break;
        case CP_ERR_SOCKET:
            snprintf(status, status_size, "创建socket失败");
            break;
        case CP_ERR_CONNECT:
            snprintf(status, status_size, "连接失败");
            break;
        case CP_ERR_WINSOCK:
            snprintf(status, status_size, "初始化Winsock失败");
            break;
        case CP_ERR_TIMEOUT:
            // 保持既有语义：TCP 的连接超时一律记「连接失败」
            if (is_wg)       snprintf(status, status_size, "WG无响应");
            else if (is_udp) snprintf(status, status_size, "UDP无响应");
            else             snprintf(status, status_size, "连接失败");
            break;
        case CP_ERR_UDP_TIMEOUT:
            if (is_wg) snprintf(status, status_size, "WG无响应");
            else       snprintf(status, status_size, "UDP无响应");
            break;
        case CP_ERR_UDP_ICMP:
            if (is_wg) snprintf(status, status_size, "WG端口不可达");
            else       snprintf(status, status_size, "UDP端口不可达");
            break;
        case CP_ERR_NO_ADDR:
            snprintf(status, status_size, "无可用地址");
            break;
        case CP_ERR_WG_NOT_WG:
            snprintf(status, status_size, "WG无有效回包");
            if (detail != NULL && detail_size > 0) {
                snprintf(detail, detail_size, "预算内收到的报文都不满足 WireGuard 结构");
            }
            break;
        default:
            snprintf(status, status_size, "未知错误");
            break;
    }
}

// ===========================================================================
// CIDR 解析与随机地址生成（严格校验）
// ===========================================================================

static bool digits_only(const char *s, size_t n) {
    if (n == 0) return false;
    for (size_t i = 0; i < n; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

int parse_ipv4_prefix(const char *prefix_str, unsigned int *ipv4_addr, int *prefix_len) {
    if (prefix_str == NULL || ipv4_addr == NULL || prefix_len == NULL) return -4;

    const char *slash = strchr(prefix_str, '/');
    if (slash == NULL) return -1; // 没有前缀长度
    if (strchr(slash + 1, '/') != NULL) return -3; // 多个 '/'

    const char *len_s = slash + 1;
    size_t len_len = strlen(len_s);
    if (!digits_only(len_s, len_len)) return -2;
    if (len_len > 2) return -2; // 前缀长度最多两位（0..32）

    long plen = 0;
    if (!parse_long_strict(len_s, 0, 32, &plen)) return -2;

    // 地址部分必须是恰好四段、每段 1~3 位纯数字、值 0..255
    std::string addr(prefix_str, (size_t)(slash - prefix_str));
    if (addr.empty()) return -3;

    unsigned int val = 0;
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        size_t dot = addr.find('.', pos);
        if (i < 3) {
            if (dot == std::string::npos) return -3;
        } else {
            if (dot != std::string::npos) return -3; // 多于四段
            dot = addr.size();
        }

        std::string seg = addr.substr(pos, dot - pos);
        if (seg.size() == 0 || seg.size() > 3) return -3;
        if (!digits_only(seg.c_str(), seg.size())) return -3;

        long v = 0;
        if (!parse_long_strict(seg.c_str(), 0, 255, &v)) return -3;
        val = (val << 8) | (unsigned int)v;
        pos = dot + 1;
    }

    *ipv4_addr = htonl(val);
    *prefix_len = (int)plen;
    return 0;
}

int parse_ipv6_prefix(const char *prefix_str, unsigned char *prefix, int *prefix_len) {
    if (prefix_str == NULL || prefix == NULL || prefix_len == NULL) return -4;

    const char *slash = strchr(prefix_str, '/');
    if (slash == NULL) return -1;
    if (strchr(slash + 1, '/') != NULL) return -3;

    const char *len_s = slash + 1;
    size_t len_len = strlen(len_s);
    if (!digits_only(len_s, len_len)) return -2;
    if (len_len > 3) return -2;

    long plen = 0;
    if (!parse_long_strict(len_s, 0, 128, &plen)) return -2;

    std::string addr(prefix_str, (size_t)(slash - prefix_str));
    if (addr.empty()) return -3;

    struct in6_addr a6;
    if (inet_pton(AF_INET6, addr.c_str(), &a6) != 1) return -3;

    memcpy(prefix, &a6, 16);
    *prefix_len = (int)plen;
    return 0;
}

// 把 128 位地址按「偏移量」加一（偏移量已知不会越过网段）
static void ipv6_add_offset(unsigned char addr[16], unsigned long long k) {
    unsigned int carry = 0;
    for (int i = 15; i >= 0; --i) {
        unsigned int sum = (unsigned int)addr[i] + (unsigned int)(k & 0xFF) + carry;
        addr[i] = (unsigned char)(sum & 0xFF);
        carry = sum >> 8;
        k >>= 8;
        if (k == 0 && carry == 0) break;
    }
}

// 随机生成一个网段内地址（IPv4）：随机补足前缀之外的所有位
void generate_random_ipv4(unsigned int ipv4_addr, int prefix_len, char *output, size_t output_size) {
    if (output == NULL || output_size == 0) return;
    if (prefix_len < 0 || prefix_len > 32) {
        if (output_size > 0) output[0] = '\0';
        return;
    }

    unsigned int base = ntohl(ipv4_addr);
    unsigned int mask = (prefix_len <= 0) ? 0u : (0xFFFFFFFFu << (32 - prefix_len));
    unsigned int host_bits = 32 - prefix_len;
    unsigned int rnd = (host_bits >= 32) ? (unsigned int)rng_u64() : rng_below_32(1u << host_bits);

    unsigned int ip = (base & mask) | (rnd & ~mask);

    struct in_addr addr;
    addr.s_addr = htonl(ip);
    if (inet_ntop(AF_INET, &addr, output, (socklen_t)output_size) == NULL) output[0] = '\0';
}

// 随机生成一个网段内地址（IPv6）：前缀之外的位随机填充
void generate_random_ipv6(const unsigned char *prefix, int prefix_len, char *output, size_t output_size) {
    if (prefix == NULL || output == NULL || output_size == 0) return;
    if (prefix_len < 0 || prefix_len > 128) { output[0] = '\0'; return; }

    unsigned char ipv6[16];
    memcpy(ipv6, prefix, 16);

    int prefix_bytes = prefix_len / 8;
    int prefix_bits = prefix_len % 8;

    // 先把掩码之外的所有位随机填满
    for (int i = prefix_bytes; i < 16; ++i) {
        ipv6[i] = (unsigned char)(rng_u64() & 0xFF);
    }
    if (prefix_bits > 0 && prefix_bytes < 16) {
        unsigned char mask = (unsigned char)(0xFF << (8 - prefix_bits));
        ipv6[prefix_bytes] = (unsigned char)((ipv6[prefix_bytes] & mask) |
                                             ((unsigned char)(rng_u64() & 0xFF) & ~mask));
    }

    struct in6_addr addr;
    memcpy(&addr, ipv6, 16);
    if (inet_ntop(AF_INET6, &addr, output, (socklen_t)output_size) == NULL) output[0] = '\0';
}

// 在 [0, total) 内不重复地取 count 个偏移量（total 必须已知且 <= 2^32）
static bool distinct_offsets(unsigned long long total, unsigned long long count,
                             std::vector<unsigned long long> &out) {
    out.clear();
    if (count == 0) return true;
    if (count > total) return false;

    out.reserve((size_t)count);

    // 网段较小时直接洗牌，简单且无偏差
    if (total <= count * 4ULL || total <= 65536ULL) {
        std::vector<unsigned long long> all((size_t)total);
        for (unsigned long long i = 0; i < total; ++i) all[(size_t)i] = i;
        for (unsigned long long i = 0; i < count; ++i) {
            unsigned long long j = i + rng_below_64(total - i);
            unsigned long long t = all[(size_t)i];
            all[(size_t)i] = all[(size_t)j];
            all[(size_t)j] = t;
        }
        out.assign(all.begin(), all.begin() + (size_t)count);
        return true;
    }

    // 大网段：Floyd 算法
    std::unordered_set<unsigned long long> seen;
    seen.reserve((size_t)count * 2);
    for (unsigned long long j = total - count; j < total; ++j) {
        unsigned long long t = rng_below_64(j + 1);
        if (seen.find(t) != seen.end()) {
            seen.insert(j);
            out.push_back(j);
        } else {
            seen.insert(t);
            out.push_back(t);
        }
    }
    return true;
}

// ===========================================================================
// IP 池 + 工作线程
// ===========================================================================

struct TestTarget {
    std::string ip_str;
    int port;
};

typedef std::stack<TestTarget> IpPool;

// 把系统层诊断追加到状态说明后面（detail 为空则直接填入）
static void append_detail(char *detail, size_t detail_size, const std::string &err) {
    if (err.empty() || detail == NULL || detail_size == 0) return;
    if (detail[0] != '\0') {
        size_t n = strlen(detail);
        if (n + 1 < detail_size) snprintf(detail + n, detail_size - n, "; %s", err.c_str());
    } else {
        snprintf(detail, detail_size, "%s", err.c_str());
    }
}

// CSV 用 snprintf 精确格式化，不经过 locale 敏感的流
static void write_result_row(FILE *csv_file, const char *target, int port, int protocol,
                             int result, double delay_ms, int resp_type,
                             const std::string &err) {
    char host_buf[NI_MAXHOST + 2];
    char hostport_buf[NI_MAXHOST + 16];
    cp_format_target(target, port, host_buf, sizeof(host_buf),
                     hostport_buf, sizeof(hostport_buf));

    char status[64];
    char detail[192];
    cp_status_text(protocol, result, resp_type, status, sizeof(status), detail, sizeof(detail));
    append_detail(detail, sizeof(detail), err);

    std::string delay_field;
    if (result == CP_OK) {
        char num[32];
        snprintf(num, sizeof(num), "%.2f", delay_ms);
        if (protocol == PROTO_WG) {
            delay_field = std::string(status) + "@" + num;
        } else {
            delay_field = num;
        }
    } else {
        delay_field = status;
    }

    fprintf(csv_file, "%s,%s,%s,%s,%s\n",
            csv_escape(target).c_str(),
            csv_escape(host_buf).c_str(),
            csv_escape(hostport_buf).c_str(),
            csv_escape(delay_field).c_str(),
            csv_escape(detail).c_str());
}

static void print_result_line(const char *target, int port, int protocol,
                             int result, double delay_ms, int resp_type,
                             const std::string &err) {
    char hostport_buf[NI_MAXHOST + 16];
    cp_format_target(target, port, NULL, 0, hostport_buf, sizeof(hostport_buf));

    char status[64];
    char detail[192];
    cp_status_text(protocol, result, resp_type, status, sizeof(status), detail, sizeof(detail));
    append_detail(detail, sizeof(detail), err);

    const char *proto_name = (protocol == PROTO_WG) ? "WireGuard"
                           : (protocol == PROTO_UDP) ? "UDP" : "TCP";

    if (result == CP_OK) {
        if (protocol == PROTO_WG) {
            printf("%s %s，延迟: %.2f ms\n", proto_name, status, delay_ms);
            if (detail[0] != '\0') printf("  说明: %s\n", detail);
        } else {
            printf("%s 连接成功 %s，延迟: %.2f ms\n", proto_name, hostport_buf, delay_ms);
        }
    } else {
        printf("%s %s: %s", proto_name, hostport_buf, status);
        if (detail[0] != '\0') printf("（%s）", detail);
        printf("\n");
    }
}

static void worker_thread_func(
    IpPool& ip_pool,
    std::mutex& pool_mutex,
    std::atomic<size_t>& tested_count,
    size_t total,
    FILE* csv_file,
    std::mutex& io_mutex,
    int protocol,
    const unsigned char* udp_payload,
    size_t udp_payload_len,
    double budget_ms)
{
    while (true) {
        TestTarget target;

        {
            std::lock_guard<std::mutex> pool_lock(pool_mutex);
            if (ip_pool.empty()) break;
            target = ip_pool.top();
            ip_pool.pop();
        }

        double delay_ms = 0.0;
        unsigned char rt = 0;
        std::string err;
        // WireGuard 的报文结构校验在 UDP 接收路径内部完成（udp_roundtrip_with_budget），
        // 这里拿到的 CP_OK 已经代表「收到了结构合法的 WG 报文」。
        int result = test_target_delay_impl(target.ip_str.c_str(), target.port, protocol,
                                           udp_payload, udp_payload_len, &delay_ms,
                                           protocol == PROTO_WG ? &rt : NULL, budget_ms, &err);

        size_t done = tested_count.fetch_add(1, std::memory_order_relaxed) + 1;

        {
            std::lock_guard<std::mutex> io_lock(io_mutex);
            printf("[%zu/%zu] ", done, total);
            print_result_line(target.ip_str.c_str(), target.port, protocol,
                              result, delay_ms, (int)rt, err);
            write_result_row(csv_file, target.ip_str.c_str(), target.port, protocol,
                             result, delay_ms, (int)rt, err);
            if ((done % 64) == 0) fflush(csv_file);
        }
    }
}

// ===========================================================================
// 参数解析小工具
// ===========================================================================

static bool parse_hex_payload(const std::string& in, std::vector<unsigned char>& out) {
    std::string hex;
    hex.reserve(in.size());

    for (size_t i = 0; i < in.size(); ) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == ':' || c == ',' || c == '-' || c == '_') {
            ++i;
            continue;
        }
        if (c == '0' && i + 3 < in.size() && (in[i + 1] == 'x' || in[i + 1] == 'X') &&
            std::isxdigit((unsigned char)in[i + 2]) && std::isxdigit((unsigned char)in[i + 3])) {
            i += 2;
            continue;
        }
        if (!std::isxdigit((unsigned char)c)) return false;
        hex.push_back((char)std::tolower((unsigned char)c));
        ++i;
    }

    if (hex.empty() || (hex.size() % 2) != 0) return false;

    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back((unsigned char)strtol(hex.substr(i, 2).c_str(), NULL, 16));
    }
    return true;
}

static bool parse_key32(const std::string& in, unsigned char out[32]) {
    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        s.push_back(c);
    }
    if (s.empty()) return false;

    if (s.size() == 64) {
        bool all_hex = true;
        for (size_t i = 0; i < s.size(); ++i) {
            if (!std::isxdigit((unsigned char)s[i])) { all_hex = false; break; }
        }
        if (all_hex) {
            for (size_t i = 0; i < 32; ++i) {
                out[i] = (unsigned char)strtol(s.substr(i * 2, 2).c_str(), NULL, 16);
            }
            return true;
        }
    }

    static const char *STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char buf[64];
    size_t n = 0;
    int val = 0, bits = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '=') break;
        const char *pos = strchr(STD, c);
        if (pos == NULL) {
            if (c == '-') pos = strchr(STD, '+');
            else if (c == '_') pos = strchr(STD, '/');
        }
        if (pos == NULL) return false;
        val = (val << 6) | (int)(pos - STD);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= sizeof(buf)) return false;
            buf[n++] = (unsigned char)((val >> bits) & 0xff);
        }
    }
    if (bits >= 6) return false;
    if (n != 32) return false;
    memcpy(out, buf, 32);
    return true;
}

static bool parse_reserved3(const std::string& in, unsigned char out[3]) {
    std::string hex;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == ':' || c == ',' || c == '-') continue;
        if (!std::isxdigit((unsigned char)c)) return false;
        hex.push_back(c);
    }
    if (hex.size() == 0 || hex.size() > 6 || (hex.size() % 2) != 0) return false;
    out[0] = out[1] = out[2] = 0;
    for (size_t i = 0; i < hex.size(); i += 2) {
        out[i / 2] = (unsigned char)strtol(hex.substr(i, 2).c_str(), NULL, 16);
    }
    return true;
}

static unsigned long long unix_nanos_now() {
    return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static const char *base64_encode(const unsigned char *in, size_t len, char *out, size_t out_size) {
    static const char *TB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = ((len + 2) / 3) * 4 + 1;
    if (out_size < need) {
        if (out_size > 0) out[0] = '\0';
        return out;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned int v = (unsigned int)in[i] << 16;
        if (i + 1 < len) v |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < len) v |= (unsigned int)in[i + 2];
        out[o++] = TB[(v >> 18) & 63];
        out[o++] = TB[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? TB[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? TB[v & 63] : '=';
    }
    out[o] = '\0';
    return out;
}

static void print_usage() {
    printf("cidr-ping —— 并行网段延迟测速\n\n");
    printf("用法: cidr-ping [选项] <主机/网段> [端口] [生成IP数量]\n\n");
    printf("选项:\n");
    printf("  --tcp                以 TCP 三次握手测速（默认）\n");
    printf("  --udp                以 UDP 发数据报并等回包测速\n");
    printf("  --udp-payload=<hex>  UDP 模式发送的载荷（十六进制，默认空数据报）\n");
    printf("                       分隔符 空格/制表/:/,/-/_ 均可，每字节可带 0x 前缀\n");
    printf("  --wg                 以 WireGuard 握手探测端点（UDP，默认端口 %d）\n", WG_DEFAULT_PORT);
    printf("  --wg-key=<base64|hex>      本端 WireGuard 私钥（32 字节，--wg 必填）\n");
    printf("  --wg-peer-key=<base64|hex> 对端公钥（默认 Cloudflare WARP）\n");
    printf("  --wg-reserved=<hex>        3 字节保留字段（默认 000000，WARP 必须为 0）\n");
    printf("  --wg-print-pubkey          打印由私钥导出的本端公钥（默认不打印）\n");
    printf("  --udp-timeout=<ms>   UDP/WG 的等待预算，默认 %.0f\n", UDP_TIMEOUT_MS);
    printf("  --tcp-timeout=<ms>   TCP 的等待预算，默认 %.0f\n", CP_DEFAULT_CONNECT_TIMEOUT_MS);
    printf("  --full               整段枚举网段内所有地址（IPv4 最多 65536 个，\n");
    printf("                       IPv6 需 /112 及更长），忽略「生成IP数量」\n");
    printf("  -h, --help           显示本帮助\n\n");
    printf("示例:\n");
    printf("  cidr-ping 192.168.1.0/24 443 50\n");
    printf("  cidr-ping --udp 162.159.192.0/24 2408 100\n");
    printf("  cidr-ping --udp --udp-payload=0x01,0x02 1.1.1.1 53 1\n");
    printf("  cidr-ping --full --wg --wg-key=<私钥> 162.159.192.0/24 %d\n", WG_DEFAULT_PORT);
    printf("\n说明:\n");
    printf("  不带 --full 时按「生成IP数量」在网段内随机采样（重复地址不会被重复测试）；\n");
    printf("  --udp-timeout / --tcp-timeout 是「整个目标」的总预算，包含 DNS 解析时间；\n");
    printf("  --wg 只在服务端确认握手有效时才回包，且回包还要通过报文结构校验；\n");
    printf("  收到 0x02 才等价于「这个端点确实是 WireGuard 服务端，且认得我们的公钥」。\n");
}

// ===========================================================================
// 主入口
// ===========================================================================

int cidr_ping_main(int argc, char *argv[]) {
    set_console_utf8();

    std::string hostips;
    long port = 443;
    long ip_count = 10;
    int protocol = PROTO_TCP;
    std::vector<unsigned char> udp_payload;
    std::vector<std::string> positional;

    bool wg_key_given = false;
    bool port_explicit = false;
    bool payload_explicit = false;
    bool enumerate_all = false;
    bool count_explicit = false;
    bool print_pubkey = false;
    unsigned char wg_priv[32];
    unsigned char wg_peer[32];
    unsigned char wg_reserved[3] = {0, 0, 0};
    double budget_ms = UDP_TIMEOUT_MS;
    double tcp_budget_ms = CP_DEFAULT_CONNECT_TIMEOUT_MS;

    memset(wg_priv, 0, sizeof(wg_priv));
    if (!parse_key32(WG_WARP_PEER_KEY_B64, wg_peer)) {
        printf("内部错误: 内置 WARP 服务端公钥解析失败\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        std::string a = (argv[i] != NULL) ? argv[i] : "";

        if (a == "--tcp") { protocol = PROTO_TCP; continue; }
        if (a == "--udp") { protocol = PROTO_UDP; continue; }
        if (a == "--wg")  { protocol = PROTO_WG; continue; }
        if (a == "--full") { enumerate_all = true; continue; }
        if (a == "--wg-print-pubkey" || a == "--wg-show-pubkey") { print_pubkey = true; continue; }
        if (a == "-h" || a == "--help") { print_usage(); return 0; }

        if (a.size() >= 9 && a.compare(0, 9, "--wg-key=") == 0) {
            if (!parse_key32(a.substr(9), wg_priv)) {
                printf("--wg-key 需要 32 字节密钥：base64（如 44 字符）或 64 位十六进制\n");
                return 1;
            }
            wg_key_given = true;
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--wg-peer-key=") == 0) {
            if (!parse_key32(a.substr(14), wg_peer)) {
                printf("--wg-peer-key 需要 32 字节密钥：base64 或 64 位十六进制\n");
                return 1;
            }
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--wg-reserved=") == 0) {
            if (!parse_reserved3(a.substr(14), wg_reserved)) {
                printf("--wg-reserved 需要 1~3 字节的十六进制（如 000000）: %s\n", a.substr(14).c_str());
                return 1;
            }
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--udp-timeout=") == 0) {
            double d = 0.0;
            if (!parse_double_strict(a.substr(14).c_str(), 1.0, 60000.0, &d)) {
                printf("--udp-timeout 需要 1~60000 之间的毫秒数: %s\n", a.substr(14).c_str());
                return 1;
            }
            budget_ms = d;
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--tcp-timeout=") == 0) {
            double d = 0.0;
            if (!parse_double_strict(a.substr(14).c_str(), 1.0, 60000.0, &d)) {
                printf("--tcp-timeout 需要 1~60000 之间的毫秒数: %s\n", a.substr(14).c_str());
                return 1;
            }
            tcp_budget_ms = d;
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--udp-payload=") == 0) {
            std::string hex = a.substr(14);
            if (!parse_hex_payload(hex, udp_payload)) {
                printf("--udp-payload 需要十六进制字符串（可含 空格/:/,/-/_ 分隔与 0x 前缀）: %s\n",
                       hex.c_str());
                return 1;
            }
            if (udp_payload.size() > 1024) {
                printf("--udp-payload 过长（%zu 字节），上限 1024 字节\n", udp_payload.size());
                return 1;
            }
            payload_explicit = true;
            continue;
        }

        // 未知开关：以 '-' 开头且第二个字符不是数字/小数点（保留 "-5" 这类负数量的校验路径）
        if (a.size() > 1 && a[0] == '-' &&
            !(std::isdigit((unsigned char)a[1]) || a[1] == '.')) {
            printf("未知参数: %s\n\n", a.c_str());
            print_usage();
            return 1;
        }
        positional.push_back(a);
    }

    if (!positional.empty()) {
        hostips = positional[0];

        if (positional.size() >= 2) {
            long v = 0;
            if (!parse_long_strict(positional[1].c_str(), 1, 65535, &v)) {
                printf("端口必须是1-65535之间的整数: %s\n", positional[1].c_str());
                return 1;
            }
            port = v;
            port_explicit = true;
        }

        if (positional.size() >= 3) {
            long v = 0;
            if (!parse_long_strict(positional[2].c_str(), 0, 100000000L, &v)) {
                printf("生成IP的数量必须是 0~100000000 之间的整数: %s\n", positional[2].c_str());
                return 1;
            }
            ip_count = v;
            count_explicit = true;
        }
    } else {
        char buf[256];

        printf("请输入主机名或IPv6网段(格式如2400:cb00:2049::/48): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            hostips = "2400:cb00:2049::/48";
        } else {
            hostips = buf;
            while (!hostips.empty() && (hostips[hostips.size() - 1] == '\n' ||
                                        hostips[hostips.size() - 1] == '\r')) {
                hostips.pop_back();
            }
            if (hostips.empty()) hostips = "2400:cb00:2049::/48";
        }

        // 交互输入同样走严格解析：非法输入重新问，最多 3 次
        for (int attempt = 0; attempt < 3; ++attempt) {
            printf("请末端口号 (默认443): ");
            if (fgets(buf, sizeof(buf), stdin) == NULL) break;
            std::string s(buf);
            while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r')) s.pop_back();
            if (s.empty()) { port = 443; break; }
            long v = 0;
            if (parse_long_strict(s.c_str(), 1, 65535, &v)) { port = v; port_explicit = true; break; }
            printf("端口必须是1-65535之间的整数，请重新输入\n");
        }

        for (int attempt = 0; attempt < 3; ++attempt) {
            printf("请输入生成IP的数量 (默认10): ");
            if (fgets(buf, sizeof(buf), stdin) == NULL) break;
            std::string s(buf);
            while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r')) s.pop_back();
            if (s.empty()) { ip_count = 10; break; }
            long v = 0;
            if (parse_long_strict(s.c_str(), 1, 100000000L, &v)) { ip_count = v; count_explicit = true; break; }
            printf("数量必须是正整数，请重新输入\n");
        }

        int dflt = (protocol == PROTO_WG) ? 3 : (protocol == PROTO_UDP ? 2 : 1);
        printf("请选择测试方式 [1] TCP [2] UDP [3] WireGuard (默认%d): ", dflt);
        if (fgets(buf, sizeof(buf), stdin) != NULL && buf[0] != '\n') {
            std::string s(buf);
            while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r')) s.pop_back();
            long choice = 0;
            if (parse_long_strict(s.c_str(), 1, 3, &choice)) {
                if (choice == 1) protocol = PROTO_TCP;
                if (choice == 2) protocol = PROTO_UDP;
                if (choice == 3) protocol = PROTO_WG;
            } else if (!s.empty()) {
                printf("测试方式只能是 1/2/3，保持默认\n");
            }
        }

        if (protocol == PROTO_WG && !wg_key_given) {
            printf("请输入 WireGuard 客户端私钥 (base64 或 64 位十六进制): ");
            if (fgets(buf, sizeof(buf), stdin) != NULL && buf[0] != '\n') {
                std::string k = buf;
                while (!k.empty() && (k[k.size() - 1] == '\n' || k[k.size() - 1] == '\r')) {
                    k.pop_back();
                }
                if (parse_key32(k, wg_priv)) {
                    wg_key_given = true;
                } else {
                    printf("私钥格式不对（既不是 32 字节 base64，也不是 64 位十六进制）\n");
                }
            }
        }
    }

    if (protocol == PROTO_WG && !port_explicit) port = WG_DEFAULT_PORT;

    // --full 时目标数量由网段本身决定，所以不再校验「生成IP数量」
    if (!enumerate_all && (ip_count <= 0 || (unsigned long long)ip_count > MAX_TARGETS)) {
        printf("生成IP的数量必须在 1~%llu 之间\n", MAX_TARGETS);
        return 1;
    }

    if (port <= 0 || port > 65535) {
        printf("端口必须是1-65535之间的数字\n");
        return 1;
    }

    if (protocol == PROTO_WG) {
        if (!wg_key_given) {
            printf("--wg 需要 --wg-key=<base64|hex> 指定本端 WireGuard 私钥\n");
            printf("（服务端只有在自己的 peer 表里找到这个公钥时才会回握手响应）\n");
            return 1;
        }

        if (payload_explicit) {
            printf("提示: --wg 模式下 --udp-payload 被忽略，载荷固定为 148 字节握手发起包\n");
        }

        // 临时私钥与 sender_index 必须来自密码学随机源；拿不到就退出，
        // 绝不退回 rand()（那会让握手包可预测、也可能被复用）。
        unsigned char eph_priv[32];
        if (!crypto_random_bytes(eph_priv, sizeof(eph_priv))) {
            printf("错误: 无法从系统获取密码学安全随机数，拒绝生成 WireGuard 握手包\n");
            return 1;
        }
        unsigned char idx_bytes[4];
        if (!crypto_random_bytes(idx_bytes, sizeof(idx_bytes))) {
            printf("错误: 无法从系统获取密码学安全随机数（sender_index）\n");
            return 1;
        }
        unsigned int sender_index = (unsigned int)idx_bytes[0] |
                                    ((unsigned int)idx_bytes[1] << 8) |
                                    ((unsigned int)idx_bytes[2] << 16) |
                                    ((unsigned int)idx_bytes[3] << 24);

        unsigned char pkt[WG_HANDSHAKE_LEN];
        if (!wg_build_handshake_initiation(pkt, wg_priv, wg_peer, wg_reserved,
                                           eph_priv, sender_index, unix_nanos_now())) {
            printf("组装 WireGuard 握手包失败（私钥或对端公钥非法）\n");
            return 1;
        }

        udp_payload.assign(pkt, pkt + WG_HANDSHAKE_LEN);

        printf("WireGuard 模式: 握手包 %d 字节, index=%u\n", (int)WG_HANDSHAKE_LEN, sender_index);
        printf("  reserved: %02x%02x%02x\n", wg_reserved[0], wg_reserved[1], wg_reserved[2]);
        if (print_pubkey) {
            unsigned char pub[32];
            char pub_b64[64];
            wg_public_key(pub, wg_priv);
            printf("  本端公钥 base64: %s\n", base64_encode(pub, 32, pub_b64, sizeof(pub_b64)));
        } else {
            printf("  （本端公钥默认不打印，需要时加 --wg-print-pubkey）\n");
        }
    } else if (protocol == PROTO_TCP && !udp_payload.empty()) {
        printf("提示: --udp-payload 仅在 --udp 模式下生效，本次按 TCP 测速已忽略\n");
    }

    // ====== Phase 1: 构建 IP 池（栈）======
    IpPool ip_pool;

    std::string::size_type slash_pos = hostips.find('/');
    if (slash_pos != std::string::npos) {
        if (hostips.find('.') != std::string::npos) {
            // ---- IPv4 CIDR ----
            unsigned int ipv4_prefix_addr;
            int ipv4_prefix_len;
            if (parse_ipv4_prefix(hostips.c_str(), &ipv4_prefix_addr, &ipv4_prefix_len) != 0) {
                printf("无效的IPv4网段格式: %s\n", hostips.c_str());
                return 1;
            }

            unsigned int base = ntohl(ipv4_prefix_addr);
            unsigned int mask = (ipv4_prefix_len <= 0) ? 0u : (0xFFFFFFFFu << (32 - ipv4_prefix_len));
            base &= mask;
            unsigned long long total = (ipv4_prefix_len >= 32)
                                       ? 1ULL
                                       : (1ULL << (32 - ipv4_prefix_len));

            if (enumerate_all) {
                if (total > 65536ULL) {
                    printf("--full 一次最多枚举 65536 个地址，%s 有 %llu 个（请用更长的前缀）\n",
                           hostips.c_str(), total);
                    return 1;
                }
                for (unsigned long long k = 0; k < total; ++k) {
                    unsigned int v = base + (unsigned int)k;
                    char ip_str[INET_ADDRSTRLEN];
                    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                             (v >> 24) & 0xFFu, (v >> 16) & 0xFFu,
                             (v >> 8) & 0xFFu, v & 0xFFu);
                    ip_pool.push(TestTarget{std::string(ip_str), (int)port});
                }
                ip_count = (long)total;
                printf("已完成IPv4整段枚举并压入IP池（栈），共 %ld 个目标\n", ip_count);
            } else {
                // 用户没显式给数量时，默认 10 只应作为「上限」：
                // 例如 /32 只有 1 个地址，就不该因为默认值而报错。
                if (!count_explicit && (unsigned long long)ip_count > total) {
                    ip_count = (long)total;
                }
                if ((unsigned long long)ip_count > total) {
                    printf("网段 %s 只有 %llu 个地址，少于请求生成的 %ld 个（--full 可整段枚举）\n",
                           hostips.c_str(), total, ip_count);
                    return 1;
                }
                std::vector<unsigned long long> offsets;
                if (!distinct_offsets(total, (unsigned long long)ip_count, offsets)) {
                    printf("无法在网段 %s 内生成 %ld 个不重复地址\n", hostips.c_str(), ip_count);
                    return 1;
                }
                for (size_t i = 0; i < offsets.size(); ++i) {
                    unsigned int v = base + (unsigned int)offsets[i];
                    char ip_str[INET_ADDRSTRLEN];
                    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                             (v >> 24) & 0xFFu, (v >> 16) & 0xFFu,
                             (v >> 8) & 0xFFu, v & 0xFFu);
                    ip_pool.push(TestTarget{std::string(ip_str), (int)port});
                }
                printf("已完成IPv4地址生成并压入IP池（栈），共 %ld 个目标（不重复）\n", ip_count);
            }
        } else {
            // ---- IPv6 CIDR ----
            unsigned char prefix[16];
            int prefix_len;
            if (parse_ipv6_prefix(hostips.c_str(), prefix, &prefix_len) != 0) {
                printf("无效的IPv6网段格式: %s\n", hostips.c_str());
                return 1;
            }

            unsigned char base6[16];
            memcpy(base6, prefix, 16);
            for (int b = prefix_len; b < 128; ++b) {
                base6[b / 8] &= (unsigned char)~(0x80 >> (b % 8));
            }

            if (enumerate_all) {
                if (prefix_len < 112) {
                    printf("--full 对 IPv6 只支持 /112 及更长的前缀: %s\n", hostips.c_str());
                    return 1;
                }
                unsigned long long total = 1ULL << (128 - prefix_len);
                for (unsigned long long k = 0; k < total; ++k) {
                    unsigned char a2[16];
                    memcpy(a2, base6, 16);
                    ipv6_add_offset(a2, k);
                    char ip_str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, a2, ip_str, sizeof(ip_str)) == NULL) {
                        snprintf(ip_str, sizeof(ip_str), "::");
                    }
                    ip_pool.push(TestTarget{std::string(ip_str), (int)port});
                }
                ip_count = (long)total;
                printf("已完成IPv6整段枚举并压入IP池（栈），共 %ld 个目标\n", ip_count);
            } else {
                // 前缀 >= /96 时地址空间不超过 2^32，可以保证不重复；
                // 更短的网段地址空间远大于任何请求数量，随机取即可。
                bool total_known = (prefix_len >= 96);
                unsigned long long total = total_known ? (1ULL << (128 - prefix_len)) : 0ULL;

                if (total_known && !count_explicit && (unsigned long long)ip_count > total) {
                    ip_count = (long)total;
                }
                if (total_known && (unsigned long long)ip_count > total) {
                    printf("网段 %s 只有 %llu 个地址，少于请求生成的 %ld 个（--full 可整段枚举）\n",
                           hostips.c_str(), total, ip_count);
                    return 1;
                }

                std::vector<unsigned long long> offsets;
                if (total_known && !distinct_offsets(total, (unsigned long long)ip_count, offsets)) {
                    printf("无法在网段 %s 内生成 %ld 个不重复地址\n", hostips.c_str(), ip_count);
                    return 1;
                }

                for (long i = 0; i < ip_count; ++i) {
                    char ip_str[INET6_ADDRSTRLEN];
                    if (total_known) {
                        unsigned char a2[16];
                        memcpy(a2, base6, 16);
                        ipv6_add_offset(a2, offsets[(size_t)i]);
                        if (inet_ntop(AF_INET6, a2, ip_str, sizeof(ip_str)) == NULL) {
                            snprintf(ip_str, sizeof(ip_str), "::");
                        }
                    } else {
                        generate_random_ipv6(base6, prefix_len, ip_str, sizeof(ip_str));
                    }
                    ip_pool.push(TestTarget{std::string(ip_str), (int)port});
                }
                printf("已完成IPv6地址生成并压入IP池（栈），共 %ld 个目标\n", ip_count);
            }
        }
    } else {
        ip_pool.push(TestTarget{hostips, (int)port});
    }

    // ====== Phase 2: 打开 CSV ======
    FILE* csv_file = fopen("rtts.csv", "w");
    if (csv_file == NULL) {
        perror("无法创建或打开rtts.csv文件");
        return 1;
    }
    fprintf(csv_file, "\xEF\xBB\xBF"); // UTF-8 BOM，Excel/WPS 直接打开无乱码
#ifdef MAIN
    fprintf(csv_file, "ip,ip_with_brackets,ip_port_with_brackets,延迟,detail\n");
#endif

    // ====== Phase 3: 多线程并行从 IP 池 pop 测速 ======
    size_t num_targets = ip_pool.size();
    if (num_targets == 0) {
        printf("没有需要测试的目标\n");
        fclose(csv_file);
        return 1;
    }

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    if (num_threads > num_targets) num_threads = (unsigned int)num_targets;

    const double active_budget = (protocol == PROTO_TCP) ? tcp_budget_ms : budget_ms;
    const char *proto_name = (protocol == PROTO_WG) ? "WireGuard"
                           : (protocol == PROTO_UDP) ? "UDP" : "TCP";
    printf("开始并行测速（%s）: IP池（栈）中有 %zu 个目标, %u 个线程\n",
           proto_name, num_targets, num_threads);
    printf("%s 总等待预算 %.0f ms（含 DNS 解析）\n", proto_name, active_budget);
    if (protocol == PROTO_UDP || protocol == PROTO_WG) {
        printf("%s 载荷 %zu 字节\n", proto_name, udp_payload.size());
    }

    std::mutex pool_mutex;
    std::atomic<size_t> tested_count(0);
    std::mutex io_mutex;

    const unsigned char *payload_ptr =
        udp_payload.empty() ? kEmptyUdpPayload : &udp_payload[0];
    size_t payload_len = udp_payload.size();

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (unsigned int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker_thread_func,
            std::ref(ip_pool), std::ref(pool_mutex), std::ref(tested_count),
            num_targets, csv_file, std::ref(io_mutex),
            protocol, payload_ptr, payload_len, active_budget);
    }

    for (size_t i = 0; i < threads.size(); ++i) {
        threads[i].join();
    }

    printf("所有测试完成，IP池剩余: %zu\n", ip_pool.size());
    fclose(csv_file);
    return 0;
}


#ifdef MAIN
int main(int argc, char *argv[]) {
    char prog[] = " ";
    argv[0] = prog;
    return cidr_ping_main(argc, argv); // 传播返回码，参数错误时进程应以非 0 退出
}
#endif