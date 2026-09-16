#include "cidr-ping.h"
#include "wireguard.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <stack>
#include <string>
#include <functional> // std::ref —— libc++ 的 <thread> 不会间接包含它（llvm-mingw / Termux）
#include <cctype>     // std::isxdigit / std::tolower —— 解析 --udp-payload 的十六进制
#include <random>     // std::random_device —— --wg 模式的临时私钥
#include <chrono>     // 稳态/系统时钟 —— TAI64N 时间戳

// ===== 测试方式 =====
enum TestProtocol {
    PROTO_TCP = 0, // 默认：非阻塞 connect() 三次握手
    PROTO_UDP = 1, // 发一个 UDP 数据报并等回包
    PROTO_WG  = 2  // 发一个 WireGuard 握手发起包，等类型 0x02 的握手响应
};

// ===== test_telnet_delay() / test_udp_delay() / test_target_delay() 的返回码 =====
#define CP_OK               0    // 成功，*delay_ms 有效
#define CP_ERR_RESOLVE     (-1)  // 域名/IP 解析失败
#define CP_ERR_SOCKET      (-2)  // 创建 socket 失败
#define CP_ERR_CONNECT     (-3)  // TCP 连接失败 / UDP 发送失败
#define CP_ERR_WINSOCK     (-4)  // WSAStartup 失败（仅 Windows）
#define CP_ERR_UDP_TIMEOUT (-5)  // UDP 在超时预算内一个回包都没收到
#define CP_ERR_UDP_ICMP    (-6)  // UDP 收到 ICMP 端口不可达：主机在线，但该端口无 UDP 服务

// UDP/WG 三次发送的等待预算按比例切分：0.5 + 0.3 + 0.2 = 1，
// 默认预算 1000ms 时刚好退化成原来的 500/300/200ms。
static const double UDP_SLICE_FRACTION[3] = {0.5, 0.3, 0.2};
#define UDP_ATTEMPTS 3
#define UDP_TIMEOUT_MS 1000.0  // --udp-timeout 的默认值

// WireGuard 模式的默认端口
#define WG_DEFAULT_PORT 2408

// 默认载荷：空数据报。UDP 允许 0 字节报文，这是最不打扰目标的探测方式。
// 用数组而不是 NULL，保证 send() 永远拿到一个合法指针。
static const unsigned char kEmptyUdpPayload[1] = {0};

#ifdef _WIN32

// Set console output to UTF-8 to fix encoding issues
void set_console_utf8() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
}

// Non-blocking TCP connect with select() for precise 1000ms timeout
int test_telnet_delay(const char *hostname, int port, double *delay_ms) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return CP_ERR_WINSOCK;
    }

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        WSACleanup();
        return CP_ERR_RESOLVE;
    }

    LARGE_INTEGER start_time, end_time, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start_time);

    SOCKET sockfd = INVALID_SOCKET;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) continue;

        // Set non-blocking
        u_long nonblock = 1;
        ioctlsocket(sockfd, FIONBIO, &nonblock);

        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            // Instant success
            QueryPerformanceCounter(&end_time);
            *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
            closesocket(sockfd); // 成功路径也必须关闭 socket，否则每次成功泄漏一个描述符
            freeaddrinfo(result);
            WSACleanup();        // 与开头的 WSAStartup 配对
            return 0;
        }

        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            continue;
        }

        // select() with 1000ms timeout
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv = {1, 0};

        int sel_ret = select((int)sockfd + 1, NULL, &wfds, NULL, &tv);

        if (sel_ret <= 0) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            if (sel_ret == 0) {
                break; // timeout —— 测试前已计时，超过 1000ms 终止（函数末尾返回 -3）
            }
            continue;
        }

        // Check SO_ERROR
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            continue;
        }

        // Success!
        QueryPerformanceCounter(&end_time);
        *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
        closesocket(sockfd); // 成功路径也必须关闭 socket，否则每次成功泄漏一个描述符
        freeaddrinfo(result);
        WSACleanup();        // 与开头的 WSAStartup 配对
        return 0;
    }

    // All attempts failed
    QueryPerformanceCounter(&end_time);
    *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;

    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    freeaddrinfo(result);
    WSACleanup();
    return CP_ERR_CONNECT;
}

// UDP 往返测速：connect() 把目标固定下来（不产生任何流量），
// 然后按计划连发数据报，用 select() 精确等待回包。
// 用 connect 而不是 sendto 的原因：只有在「已连接」的 UDP socket 上，
// ICMP 端口不可达才会作为 WSAECONNRESET 回传给 recv()，从而把
// 「主机在线但端口没服务」和「根本没响应」区分开。
//
// resp_type 可为 NULL；非 NULL 时成功回包会把首字节写进去 —— WireGuard 模式下
// 用它区分「握手响应 0x02 / cookie 0x03 / 其他」。
// budget_ms 是三次发送加等待的总预算（--udp-timeout）。
int test_udp_delay(const char *hostname, int port,
                   const unsigned char *payload, size_t payload_len,
                   double *delay_ms, unsigned char *resp_type,
                   double budget_ms) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return CP_ERR_WINSOCK;
    }

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM; // 与 TCP 版唯一的关键差异

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        WSACleanup();
        return CP_ERR_RESOLVE;
    }

    LARGE_INTEGER start_time, now, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start_time);

    int final_rc = CP_ERR_UDP_TIMEOUT;
    SOCKET sockfd = INVALID_SOCKET;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) continue;

        // 设成非阻塞：select() 报可读之后 recv() 绝不会再卡住
        u_long nonblock = 1;
        ioctlsocket(sockfd, FIONBIO, &nonblock);

        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) != 0) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            continue;
        }

        final_rc = CP_ERR_UDP_TIMEOUT;

        for (int attempt = 0; attempt < UDP_ATTEMPTS; ++attempt) {
            QueryPerformanceCounter(&now);
            double used = (double)(now.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
            double remaining = budget_ms - used;
            if (remaining <= 0.0) break; // 预算用完

            double slice = budget_ms * UDP_SLICE_FRACTION[attempt];
            if (slice > remaining) slice = remaining;

            if (send(sockfd, (const char *)payload, (int)payload_len, 0) == SOCKET_ERROR) {
                final_rc = CP_ERR_CONNECT;
                break;
            }

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec = (long)(slice / 1000.0);
            tv.tv_usec = (long)((slice - (double)tv.tv_sec * 1000.0) * 1000.0);

            int sel_ret = select((int)sockfd + 1, &rfds, NULL, NULL, &tv);
            if (sel_ret < 0) {
                final_rc = CP_ERR_CONNECT;
                break;
            }
            if (sel_ret == 0) {
                continue; // 这一轮没等到，按计划补发
            }

            char buf[1024];
            int n = recv(sockfd, buf, sizeof(buf), 0);
            if (n >= 0) {
                if (resp_type != NULL && n >= 1) {
                    *resp_type = (unsigned char)buf[0];
                }
                QueryPerformanceCounter(&now);
                *delay_ms = (double)(now.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
                closesocket(sockfd);
                freeaddrinfo(result);
                WSACleanup();
                return CP_OK;
            }
            int recv_err = WSAGetLastError();
            if (recv_err == WSAEWOULDBLOCK) {
                continue; // 非阻塞 socket 的正常“暂时没数据”，当作本轮没等到
            }
            if (recv_err == WSAECONNRESET) {
                // ICMP 端口不可达：主机在线，但该 UDP 端口没有服务在听
                QueryPerformanceCounter(&now);
                *delay_ms = (double)(now.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
                closesocket(sockfd);
                freeaddrinfo(result);
                WSACleanup();
                return CP_ERR_UDP_ICMP;
            }
            final_rc = CP_ERR_CONNECT;
            break;
        }

        if (sockfd != INVALID_SOCKET) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
        }
        if (final_rc == CP_ERR_UDP_TIMEOUT) {
            break; // 超时：与 TCP 版一致，不再尝试下一个地址
        }
    }

    QueryPerformanceCounter(&now);
    *delay_ms = (double)(now.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;

    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    freeaddrinfo(result);
    WSACleanup();
    return final_rc;
}

#else // POSIX

#include <fcntl.h>      // fcntl(), O_NONBLOCK
#include <sys/select.h> // select(), fd_set

void set_console_utf8() {
    // Not needed for POSIX systems
}

// Non-blocking TCP connect with select() for precise 1000ms timeout
int test_telnet_delay(const char *hostname, int port, double *delay_ms) {
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        return CP_ERR_RESOLVE;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    int sockfd = -1;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd < 0) continue;

        // Set non-blocking
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) == 0) {
            gettimeofday(&end_time, NULL);
            *delay_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                        (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            close(sockfd); // 成功路径也必须关闭 socket，否则每次成功泄漏一个 fd
            freeaddrinfo(result);
            return 0;
        }

        if (errno != EINPROGRESS) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        // select() with 1000ms timeout
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);
        struct timeval tv = {1, 0};

        int sel_ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);

        if (sel_ret <= 0) {
            close(sockfd);
            sockfd = -1;
            if (sel_ret == 0) {
                break; // timeout —— 测试前已计时，超过 1000ms 终止（函数末尾返回 -3）
            }
            continue;
        }

        // Check SO_ERROR
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        // Success!
        gettimeofday(&end_time, NULL);
        *delay_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                    (end_time.tv_usec - start_time.tv_usec) / 1000.0;
        close(sockfd); // 成功路径也必须关闭 socket，否则每次成功泄漏一个 fd
        freeaddrinfo(result);
        return 0;
    }

    // All attempts failed
    gettimeofday(&end_time, NULL);
    *delay_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                (end_time.tv_usec - start_time.tv_usec) / 1000.0;

    if (sockfd >= 0) close(sockfd);
    freeaddrinfo(result);
    return CP_ERR_CONNECT;
}

// UDP 往返测速 —— 逻辑与 Windows 分支一致，只是 ICMP 端口不可达在
// Linux 上表现为 recv() 返回 -1 且 errno == ECONNREFUSED。
int test_udp_delay(const char *hostname, int port,
                   const unsigned char *payload, size_t payload_len,
                   double *delay_ms, unsigned char *resp_type,
                   double budget_ms) {
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        return CP_ERR_RESOLVE;
    }

    struct timeval start_time, now;
    gettimeofday(&start_time, NULL);

    int final_rc = CP_ERR_UDP_TIMEOUT;
    int sockfd = -1;

    for (struct addrinfo *ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd < 0) continue;

        // 设成非阻塞：select() 说可读之后 recv() 就绝不会再阻塞住，
        // 即使这里有「可读事件被抢走」的极端竞争，也只会拿到 EAGAIN。
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        // connect() 对 UDP 不产生流量，只是固定目标：
        // 之后 ICMP 端口不可达才会回传给 recv()（errno == ECONNREFUSED）
        if (connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen) != 0) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        final_rc = CP_ERR_UDP_TIMEOUT;

        for (int attempt = 0; attempt < UDP_ATTEMPTS; ++attempt) {
            gettimeofday(&now, NULL);
            double used = (now.tv_sec - start_time.tv_sec) * 1000.0 +
                          (now.tv_usec - start_time.tv_usec) / 1000.0;
            double remaining = budget_ms - used;
            if (remaining <= 0.0) break; // 预算用完

            double slice = budget_ms * UDP_SLICE_FRACTION[attempt];
            if (slice > remaining) slice = remaining;

            if (send(sockfd, payload, payload_len, 0) < 0) {
                final_rc = CP_ERR_CONNECT;
                break;
            }

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec = (long)(slice / 1000.0);
            tv.tv_usec = (long)((slice - (double)tv.tv_sec * 1000.0) * 1000.0);

            // 注意参数顺序：readfds 是第 2 个参数。
            // 第 3 个位置是 writefds —— UDP 永远可写，传错会变成「立刻返回然后阻塞在 recv」
            int sel_ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
            if (sel_ret < 0) {
                final_rc = CP_ERR_CONNECT;
                break;
            }
            if (sel_ret == 0) {
                continue; // 这一轮没等到，按计划补发
            }

            char buf[1024];
            ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                continue; // 非阻塞 socket 的正常“暂时没数据”，当作本轮没等到
            }
            if (n >= 0) {
                if (resp_type != NULL && n >= 1) {
                    *resp_type = (unsigned char)buf[0];
                }
                gettimeofday(&now, NULL);
                *delay_ms = (now.tv_sec - start_time.tv_sec) * 1000.0 +
                            (now.tv_usec - start_time.tv_usec) / 1000.0;
                close(sockfd);
                freeaddrinfo(result);
                return CP_OK;
            }
            if (errno == ECONNREFUSED) {
                // ICMP 端口不可达：主机在线，但该 UDP 端口没有服务在听
                gettimeofday(&now, NULL);
                *delay_ms = (now.tv_sec - start_time.tv_sec) * 1000.0 +
                            (now.tv_usec - start_time.tv_usec) / 1000.0;
                close(sockfd);
                freeaddrinfo(result);
                return CP_ERR_UDP_ICMP;
            }
            final_rc = CP_ERR_CONNECT;
            break;
        }

        if (sockfd >= 0) {
            close(sockfd);
            sockfd = -1;
        }
        if (final_rc == CP_ERR_UDP_TIMEOUT) {
            break; // 超时：与 TCP 版一致，不再尝试下一个地址
        }
    }

    gettimeofday(&now, NULL);
    *delay_ms = (now.tv_sec - start_time.tv_sec) * 1000.0 +
                (now.tv_usec - start_time.tv_usec) / 1000.0;

    if (sockfd >= 0) close(sockfd);
    freeaddrinfo(result);
    return final_rc;
}

#endif

// 按测试方式分发。
// TCP 走三次握手；UDP 与 WireGuard 都走「发一个 UDP 数据报并等回包」这一条传输路径，
// 区别只在载荷（WG 是 148 字节握手发起包）和结果的解读方式。
int test_target_delay(const char *hostname, int port, int protocol,
                      const unsigned char *udp_payload, size_t udp_payload_len,
                      double *delay_ms, unsigned char *resp_type,
                      double budget_ms) {
    if (protocol == PROTO_UDP || protocol == PROTO_WG) {
        return test_udp_delay(hostname, port, udp_payload, udp_payload_len,
                              delay_ms, resp_type, budget_ms);
    }
    return test_telnet_delay(hostname, port, delay_ms);
}

// 把 WireGuard 回包的首字节翻译成可读的说明 + CSV 单元格文本
static const char *wg_resp_text(unsigned char t, char *buf, size_t buf_size) {
    switch (t) {
        case WG_MSG_HANDSHAKE_RESPONSE:
            return "握手响应(0x02)";
        case WG_MSG_COOKIE_REPLY:
            return "Cookie回复(0x03)";
        case WG_MSG_HANDSHAKE_INITIATION:
            return "握手发起(0x01)";
        case WG_MSG_TRANSPORT_DATA:
            return "传输数据(0x04)";
        default:
            snprintf(buf, buf_size, "回包(0x%02x)", (unsigned)t);
            return buf;
    }
}

// 显示结果
// resp_type 仅 WireGuard 模式有意义：回包的首字节（0x02 = 真握手响应）
void display_result(int protocol, const char *hostname, int port, int result,
                    double delay_ms, int resp_type, FILE *csv_file) {
    char formatted_host_port[NI_MAXHOST + 10]; // Enough space for IPv6 + port
    char formatted_host[NI_MAXHOST];

    if (strchr(hostname, ':') != NULL) { // Likely IPv6
        snprintf(formatted_host_port, sizeof(formatted_host_port), "[%s]:%d", hostname, port);
        snprintf(formatted_host, sizeof(formatted_host), "[%s]", hostname);
    } else { // Likely IPv4
        snprintf(formatted_host_port, sizeof(formatted_host_port), "%s:%d", hostname, port);
        snprintf(formatted_host, sizeof(formatted_host), "%s", hostname);
    }

    char wgbuf[24];
    switch (result) {
        case CP_OK: // Success
            if (protocol == PROTO_WG) {
                const char *txt = wg_resp_text((unsigned char)resp_type, wgbuf, sizeof(wgbuf));
                printf("WireGuard %s，延迟: %.2f ms\n", txt, delay_ms);
                fprintf(csv_file, "%s,%s,%s,WG%s@%.2f\n",
                        hostname, formatted_host, formatted_host_port, txt, delay_ms);
            } else if (protocol == PROTO_UDP) {
                printf("UDP 收到回包，延迟: %.2f ms\n", delay_ms);
                fprintf(csv_file, "%s,%s,%s,%.2f\n", hostname, formatted_host, formatted_host_port, delay_ms);
            } else {
                printf("连接成功，延迟: %.2f ms\n", delay_ms);
                fprintf(csv_file, "%s,%s,%s,%.2f\n", hostname, formatted_host, formatted_host_port, delay_ms);
            }
            break;
        case CP_ERR_RESOLVE: // Failed to get host info
            printf("无法解析主机名: %s\n", hostname);
            fprintf(csv_file, "%s,%s,%s,无法解析主机名\n", hostname, formatted_host, formatted_host_port);
            break;
        case CP_ERR_SOCKET: // Failed to create socket (This error code is not used in the general version, but kept for consistency)
            printf("创建socket失败\n");
            fprintf(csv_file, "%s,%s,%s,创建socket失败\n", hostname, formatted_host, formatted_host_port);
            break;
        case CP_ERR_CONNECT: // TCP connect / UDP send failed
            printf("连接到 %s:%d 失败\n", hostname, port);
            fprintf(csv_file, "%s,%s,%s,连接失败\n", hostname, formatted_host, formatted_host_port);
            break;
        case CP_ERR_WINSOCK: // Failed to initialize Winsock (Windows-specific, but kept for consistency)
            printf("初始化Winsock失败\n");
            fprintf(csv_file, "%s,%s,%s,初始化Winsock失败\n", hostname, formatted_host, formatted_host_port);
            break;
        case CP_ERR_UDP_TIMEOUT: // UDP/WG：三次发送全部没等到回包
            if (protocol == PROTO_WG) {
                printf("WireGuard 无响应（超时预算内未收到回包）\n");
                fprintf(csv_file, "%s,%s,%s,WG无响应\n", hostname, formatted_host, formatted_host_port);
            } else {
                printf("UDP 无响应（超时预算内未收到回包）\n");
                fprintf(csv_file, "%s,%s,%s,UDP无响应\n", hostname, formatted_host, formatted_host_port);
            }
            break;
        case CP_ERR_UDP_ICMP: // UDP/WG：收到 ICMP 端口不可达，主机在线但端口无服务
            if (protocol == PROTO_WG) {
                printf("WireGuard 端口不可达（收到 ICMP，主机在线）\n");
                fprintf(csv_file, "%s,%s,%s,WG端口不可达\n", hostname, formatted_host, formatted_host_port);
            } else {
                printf("UDP 端口不可达（收到 ICMP，主机在线）\n");
                fprintf(csv_file, "%s,%s,%s,UDP端口不可达\n", hostname, formatted_host, formatted_host_port);
            }
            break;
        default:
            printf("未知错误\n");
            fprintf(csv_file, "%s,%s,%s,未知错误\n", hostname, formatted_host, formatted_host_port);
            break;
    }
}

int parse_ipv4_prefix(const char *prefix_str, unsigned int *ipv4_addr, int *prefix_len) {
    char temp[256];
    char *slash_pos;

    strncpy(temp, prefix_str, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    slash_pos = strchr(temp, '/');
    if (slash_pos == NULL) {
        return -1; // No prefix length found
    }

    *slash_pos = '\0';
    *prefix_len = atoi(slash_pos + 1);

    if (*prefix_len < 0 || *prefix_len > 32) {
        return -2; // Invalid prefix length
    }

    // Parse IPv4 address
    unsigned int addr_val = 0;
    int part;
    char *token = strtok(temp, ".");
    for (int i = 0; i < 4; i++) {
        if (token == NULL) {
            return -3; // Invalid IPv4 address format
        }
        part = atoi(token);
        if (part < 0 || part > 255) {
            return -3; // Invalid IPv4 address part
        }
        addr_val = (addr_val << 8) | part;
        token = strtok(NULL, ".");
    }
#ifdef _WIN32
    *ipv4_addr = htonl(addr_val); // Convert to network byte order
#else
    *ipv4_addr = htonl(addr_val); // Convert to network byte order
#endif

    return 0;
}

// 解析IPv6网段，例如"2400:cb00:2049::/48"
int parse_ipv6_prefix(const char *prefix_str, unsigned char *prefix, int *prefix_len) {
    char temp[256];
    char *slash_pos;
    
    // 复制前缀字符串以便修改
    strncpy(temp, prefix_str, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';
    
    // 查找斜杠位置
    slash_pos = strchr(temp, '/');
    if (slash_pos == NULL) {
        return -1; // 没有找到前缀长度
    }
    
    // 分割字符串
    *slash_pos = '\0';
    *prefix_len = atoi(slash_pos + 1);
    
    // 验证前缀长度
    if (*prefix_len < 0 || *prefix_len > 128) {
        return -2; // 无效的前缀长度
    }
    
    // 解析IPv6地址
    struct in6_addr addr;
    if (inet_pton(AF_INET6, temp, &addr) != 1) {
        return -3; // 无效的IPv6地址
    }
    
    // 复制地址到输出
    memcpy(prefix, &addr, 16);
    
    return 0;
}

void generate_random_ipv4(unsigned int ipv4_addr, int prefix_len, char *output, size_t output_size) {
    unsigned int random_ip = ntohl(ipv4_addr);
    // prefix_len == 0 时 0xFFFFFFFF << 32 是未定义行为，单独处理
    unsigned int mask = (prefix_len <= 0) ? 0u : (0xFFFFFFFFu << (32 - prefix_len));
    unsigned int random_suffix = rand();

    random_ip = (random_ip & mask) | (random_suffix & ~mask);

    struct in_addr addr;
    addr.s_addr = htonl(random_ip);
    inet_ntop(AF_INET, &addr, output, output_size);
}

// 生成随机IPv6地址，基于给定的前缀
void generate_random_ipv6(const unsigned char *prefix, int prefix_len, char *output, size_t output_size) {
    unsigned char ipv6[16];
    struct in6_addr addr;
    int prefix_bytes = prefix_len / 8;
    int prefix_bits = prefix_len % 8;
    
    // 复制前缀部分
    memcpy(ipv6, prefix, 16);
    
    // 生成随机位
    for (int i = prefix_bytes; i < 16; i++) {
        ipv6[i] = (unsigned char)rand();
    }
    
    // 处理部分字节的前缀
    if (prefix_bits > 0) {
        unsigned char mask = (unsigned char)(0xFF << (8 - prefix_bits));
        ipv6[prefix_bytes] = (ipv6[prefix_bytes] & mask) | ((unsigned char)rand() & ~mask);
    }
    
    // 转换为字符串
    memcpy(&addr, ipv6, 16);
    inet_ntop(AF_INET6, &addr, output, output_size);
}

// 测试目标 — 阶段1在单线程中一次性生成，构成待测IP池的元素
struct TestTarget {
    std::string ip_str;
    int port;
};

// IP池：栈（LIFO）数据类型，所有待测IP先全部压栈，线程再从栈顶取（pop）出来测速
typedef std::stack<TestTarget> IpPool;

// Worker thread function — 多线程并行测速
// 每个线程循环：加锁 → 从栈顶pop一个IP → 解锁 → 测速
// pop必须加锁：std::stack本身不是线程安全的，若不加锁并发pop会破坏容器内部状态、
// 造成同一个IP被多个线程取走或容器崩溃
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

        // ===== 临界区：并发pop由互斥锁限制，同一时刻只有一个线程能出栈 =====
        {
            std::lock_guard<std::mutex> pool_lock(pool_mutex);
            if (ip_pool.empty()) {
                break; // 池已空，该线程结束（锁在离开作用域时自动释放）
            }
            target = ip_pool.top(); // 取栈顶元素
            ip_pool.pop();          // 出栈，该IP从此只属于本线程
        }
        // ===== 临界区结束：测速在锁外进行，多个线程可真正并行，不会互相串行化 =====

        // 每个独立线程在测试前计时（test_*_delay 内部开始计时）
        double delay_ms = 0.0;
        int resp_type = -1; // WireGuard 模式下由回包首字节填充
        unsigned char rt = 0;
        int result = test_target_delay(target.ip_str.c_str(), target.port, protocol,
                                       udp_payload, udp_payload_len, &delay_ms,
                                       protocol == PROTO_WG ? &rt : NULL, budget_ms);
        if (protocol == PROTO_WG) {
            resp_type = (int)rt;
        }

        size_t done = tested_count.fetch_add(1, std::memory_order_relaxed) + 1;

        // 加锁保证线程安全的I/O输出
        {
            std::lock_guard<std::mutex> io_lock(io_mutex);
            printf("[%zu/%zu] ", done, total);
            display_result(protocol, target.ip_str.c_str(), target.port, result,
                           delay_ms, resp_type, csv_file);
        }
    }
}

// 解析 --udp-payload 的十六进制字符串。
// 允许 空格/制表/冒号/逗号/短横线/下划线 作文本分隔，也允许每字节带 0x / 0X 前缀，
// 例如 "041d69"、"04 1d 69"、"0x04,0x1d,0x69" 都解析成同一个 3 字节载荷。
// 分隔符只在「不是十六进制数字」时才起作用，所以 "0x0a0b" 不会被误切。
static bool parse_hex_payload(const std::string& in, std::vector<unsigned char>& out) {
    std::string hex;
    hex.reserve(in.size());

    for (size_t i = 0; i < in.size(); ) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == ':' || c == ',' || c == '-' || c == '_') {
            ++i;
            continue;
        }
        // 仅当 "0x" 后面确实跟着两个十六进制数字时，才把它当作前缀剥掉，
        // 否则 "0x0" 这种残缺写法会退化成把 'x' 当作非法字符报错。
        if (c == '0' && i + 3 < in.size() && (in[i + 1] == 'x' || in[i + 1] == 'X') &&
            std::isxdigit((unsigned char)in[i + 2]) && std::isxdigit((unsigned char)in[i + 3])) {
            i += 2;
            continue;
        }
        if (!std::isxdigit((unsigned char)c)) {
            return false;
        }
        hex.push_back((char)std::tolower((unsigned char)c));
        ++i;
    }

    if (hex.empty() || (hex.size() % 2) != 0) {
        return false;
    }

    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back((unsigned char)strtol(hex.substr(i, 2).c_str(), NULL, 16));
    }
    return true;
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
    printf("  --udp-timeout=<ms>   UDP/WG 的等待预算，默认 %.0f\n", UDP_TIMEOUT_MS);
    printf("  --full               整段枚举网段内所有地址（IPv4 最多 65536 个，\n");
    printf("                       IPv6 需 /112 及更长），忽略「生成IP数量」\n");
    printf("  -h, --help           显示本帮助\n\n");
    printf("示例:\n");
    printf("  cidr-ping 192.168.1.0/24 443 50\n");
    printf("  cidr-ping --udp 162.159.192.0/24 2408 100\n");
    printf("  cidr-ping --udp --udp-payload=0x01,0x02 1.1.1.1 53 1\n");
    printf("  cidr-ping --full --wg --wg-key=<私钥> 162.159.192.0/24 %d\n", WG_DEFAULT_PORT);
    printf("\n说明:\n");
    printf("  不带 --full 时按「生成IP数量」在网段内随机采样（老行为）；\n");
    printf("  --wg 只在服务端确认握手有效时才回包，因此「收到 0x02」等价于\n");
    printf("  「这个端点确实是 WireGuard 服务端，且认得我们的公钥」。\n");
}

// 解析 32 字节密钥：接受 base64（标准或 URL-safe，可省略 '='）或 64 位十六进制。
// 两种写法都允许夹带空白，方便直接从配置文件里粘贴。
static bool parse_key32(const std::string& in, unsigned char out[32]) {
    std::string s;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        s.push_back(c);
    }
    if (s.empty()) return false;

    // ① 64 位十六进制
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

    // ② base64。这里刻意只接受「按键值当普通 base64」的写法：
    //    43 个字符 + '=' 是标准 base64 输出的 32 字节密钥长度。
    static const char *STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char buf[64];
    size_t n = 0;
    int val = 0, bits = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '=') break;
        const char *pos = strchr(STD, c);
        if (pos == NULL) {
            // URL-safe 变体
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
    if (bits >= 6) return false; // 尾部残留字符数不合法（例如多打了一个字符）
    if (n != 32) return false;
    memcpy(out, buf, 32);
    return true;
}

// 解析 --wg-reserved：1~3 个字节的十六进制（写成 6 位、4 位、2 位都行）
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

// 当前 Unix 时间（纳秒）。WireGuard 的 TAI64N 时间戳由它换算而来，
// 服务端会用时间戳做重放保护，所以不能用固定值。
static unsigned long long unix_nanos_now() {
    return (unsigned long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// 取一个 32 位随机数。std::random_device 在某些 MinGW/libc++/bionic 上会退化成
// 确定性引擎、甚至直接抛异常（拿不到熵源），所以这里吞掉异常并让调用方再掺别的熵。
static unsigned int random_u32() {
    try {
        std::random_device rd;
        return rd();
    } catch (...) {
        return 0;
    }
}

// 取 n 字节随机数。
// 无论 random_device 是否可用，都再掺入 rand()（已用 time() 播种）和纳秒时间，
// 保证每次运行拿到的临时私钥都不一样。
static void random_bytes(unsigned char *out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned int v = random_u32();
        v ^= ((unsigned int)rand() << 7) ^ ((unsigned int)rand() << 17);
        v ^= (unsigned int)(unix_nanos_now() >> ((i % 24) + 3));
        out[i] = (unsigned char)(v & 0xff);
    }
}

// 标准 base64 编码，只在启动时打印本端公钥用得到
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

int cidr_ping_main(int argc, char *argv[]) {
    set_console_utf8();
    srand((unsigned int)time(NULL));

    // ====== Parse arguments ======
    // 先摘出 --xxx 开关，剩下的参数仍按原有位置顺序解释为 <主机/网段> [端口] [数量]。
    // 一个位置参数都没有时进入交互模式（与旧版 argc<2 的行为一致），
    // 所以 --tcp / --udp 放在位置参数的前面或后面都可以，旧的命令行写法完全不受影响。
    std::string hostips;
    int port = 443;
    int ip_count = 10;
    int protocol = PROTO_TCP; // 默认 TCP
    std::vector<unsigned char> udp_payload;
    std::vector<std::string> positional;

    // ===== WireGuard 参数 =====
    bool wg_key_given = false;
    bool port_explicit = false;
    bool payload_explicit = false;
    bool enumerate_all = false;
    unsigned char wg_priv[32];
    unsigned char wg_peer[32];
    unsigned char wg_reserved[3] = {0, 0, 0};
    double budget_ms = UDP_TIMEOUT_MS;

    memset(wg_priv, 0, sizeof(wg_priv));
    if (!parse_key32(WG_WARP_PEER_KEY_B64, wg_peer)) {
        printf("内部错误: 内置 WARP 服务端公钥解析失败\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        std::string a = (argv[i] != NULL) ? argv[i] : "";

        if (a == "--tcp") {
            protocol = PROTO_TCP;
            continue;
        }
        if (a == "--udp") {
            protocol = PROTO_UDP;
            continue;
        }
        if (a == "--wg") {
            protocol = PROTO_WG;
            continue;
        }
        if (a == "--full") {
            enumerate_all = true;
            continue;
        }
        if (a == "-h" || a == "--help") {
            print_usage();
            return 0;
        }
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
                printf("--wg-reserved 需要 1~3 字节的十六进制（如 000000）: %s\n",
                       a.substr(14).c_str());
                return 1;
            }
            continue;
        }
        if (a.size() >= 14 && a.compare(0, 14, "--udp-timeout=") == 0) {
            std::string v = a.substr(14);
            char *end = NULL;
            double d = strtod(v.c_str(), &end);
            if (end == v.c_str() || end == NULL || *end != '\0' || !(d > 0.0) || d > 60000.0) {
                printf("--udp-timeout 需要 0~60000 之间的毫秒数: %s\n", v.c_str());
                return 1;
            }
            budget_ms = d;
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
        // 未知开关：以 -- 开头，或 '-' 后接非数字。
        // 带上数字判断是为了让 "-5" 这类负的 IP 数量仍然走位置参数，
        // 从而保留原有的「数量必须大于 0」报错路径。
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
            port = atoi(positional[1].c_str());
            port_explicit = true;
            if (positional.size() >= 3) {
                ip_count = atoi(positional[2].c_str());
            }
        }
    } else {
        char buf[256];
        printf("请输入主机名或IPv6网段(格式如2400:cb00:2049::/48): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL || buf[0] == '\n') {
            hostips = "2400:cb00:2049::/48";
        } else {
            hostips = buf;
            size_t len = hostips.length();
            if (len > 0 && hostips[len-1] == '\n') {
                hostips.pop_back();
            }
        }

        printf("请末端口号 (默认443): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL || buf[0] == '\n') {
            port = 443;
        } else {
            port = atoi(buf);
            port_explicit = true;
        }

        printf("请输入生成IP的数量 (默认10): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL || buf[0] == '\n') {
            ip_count = 10;
        } else {
            ip_count = atoi(buf);
        }

        // 协议问句放在最后：这样以前「喂三行输入」的用法仍然有效，
        // 第四行读不到时保持命令行上 --tcp/--udp/--wg 给出的默认值。
        int dflt = (protocol == PROTO_WG) ? 3 : (protocol == PROTO_UDP ? 2 : 1);
        printf("请选择测试方式 [1] TCP [2] UDP [3] WireGuard (默认%d): ", dflt);
        if (fgets(buf, sizeof(buf), stdin) != NULL && buf[0] != '\n') {
            int choice = atoi(buf);
            if (choice == 1) protocol = PROTO_TCP;
            if (choice == 2) protocol = PROTO_UDP;
            if (choice == 3) protocol = PROTO_WG;
        }

        // 选了 WireGuard 又没在命令行给过私钥，就再问一行。
        // 这一行只在第 3 种模式下出现，前四种输入的脚本不受影响。
        if (protocol == PROTO_WG && !wg_key_given) {
            printf("请输入 WireGuard 客户端私钥 (base64 或 64 位十六进制): ");
            if (fgets(buf, sizeof(buf), stdin) != NULL && buf[0] != '\n') {
                std::string k = buf;
                while (!k.empty() && (k[k.size()-1] == '\n' || k[k.size()-1] == '\r')) {
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

    // --wg 没显式给端口时默认走 WARP 的 2408
    if (protocol == PROTO_WG && !port_explicit) {
        port = WG_DEFAULT_PORT;
    }

    // --full 时目标数量由网段本身决定，所以不再校验「生成IP数量」
    if (ip_count <= 0 && !enumerate_all) {
        printf("生成IP的数量必须大于0\n");
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

        // 整个扫描只组装一次握手包，所有目标共用 —— 与 chunfengyao/wg-endip 的做法一致。
        // 包里的 mac1 只依赖对端公钥，encrypted_static / encrypted_timestamp 也跟目标无关，
        // 所以同一个包打给任意 WARP 端点都成立。
        unsigned char eph_priv[32];
        random_bytes(eph_priv, sizeof(eph_priv));

        unsigned char pkt[WG_HANDSHAKE_LEN];
        // rand() 用 time() 播种，同一秒内连跑两次会拿到同一个序列，
        // 所以再异或一下纳秒时间，让 index 也做到每次运行都不同。
        unsigned int sender_index = ((unsigned int)rand() << 16) ^ (unsigned int)rand() ^
                                    (unsigned int)unix_nanos_now();
        if (!wg_build_handshake_initiation(pkt, wg_priv, wg_peer, wg_reserved,
                                           eph_priv, sender_index, unix_nanos_now())) {
            printf("组装 WireGuard 握手包失败（私钥或对端公钥非法）\n");
            return 1;
        }

        udp_payload.assign(pkt, pkt + WG_HANDSHAKE_LEN);

        unsigned char pub[32];
        wg_public_key(pub, wg_priv);
        char pub_b64[64];
        printf("WireGuard 模式: 握手包 %d 字节, index=%u\n", (int)WG_HANDSHAKE_LEN, sender_index);
        printf("  本端公钥 base64: %s\n", base64_encode(pub, 32, pub_b64, sizeof(pub_b64)));
        printf("  reserved: %02x%02x%02x\n", wg_reserved[0], wg_reserved[1], wg_reserved[2]);
    } else if (protocol == PROTO_TCP && !udp_payload.empty()) {
        printf("提示: --udp-payload 仅在 --udp 模式下生效，本次按 TCP 测速已忽略\n");
    }

    // ====== Phase 1: Build the IP pool (stack) ======
    // 在测速前先把所有待测IP一次性压入IP池（栈），保证rand()只在单线程中调用（rand()非线程安全）
    IpPool ip_pool;

    std::string::size_type slash_pos = hostips.find('/');
    if (slash_pos != std::string::npos) {
        if (hostips.find('.') != std::string::npos) {
            // IPv4 CIDR
            unsigned int ipv4_prefix_addr;
            int ipv4_prefix_len;
            if (parse_ipv4_prefix(hostips.c_str(), &ipv4_prefix_addr, &ipv4_prefix_len) != 0) {
                printf("无效的IPv4网段格式: %s\n", hostips.c_str());
                return 1;
            }

            if (enumerate_all) {
                // 整段枚举：不做随机采样，按顺序把网段里的每个地址都压进池子。
                // 对「找可用端点」这种目的，整段扫一遍既不会漏，
                // 探测量也比随机采样凑覆盖率少得多。
                unsigned int base = ntohl(ipv4_prefix_addr);
                unsigned int mask = (ipv4_prefix_len <= 0) ? 0u
                                    : (0xFFFFFFFFu << (32 - ipv4_prefix_len));
                base &= mask;
                unsigned long long total = (ipv4_prefix_len >= 32)
                                           ? 1ULL
                                           : (1ULL << (32 - ipv4_prefix_len));
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
                    ip_pool.push(TestTarget{std::string(ip_str), port});
                }
                ip_count = (int)total;
                printf("已完成IPv4整段枚举并压入IP池（栈），共 %d 个目标\n", ip_count);
            } else {
                for (int i = 0; i < ip_count; i++) {
                    char ip_str[INET_ADDRSTRLEN];
                    generate_random_ipv4(ipv4_prefix_addr, ipv4_prefix_len, ip_str, sizeof(ip_str));
                    ip_pool.push(TestTarget{std::string(ip_str), port}); // 压栈
                }
                printf("已完成IPv4地址生成并压入IP池（栈），共 %d 个目标\n", ip_count);
            }
        } else {
            // IPv6 CIDR
            unsigned char prefix[16];
            int prefix_len;
            if (parse_ipv6_prefix(hostips.c_str(), prefix, &prefix_len) != 0) {
                printf("无效的IPv6网段格式: %s\n", hostips.c_str());
                return 1;
            }

            if (enumerate_all) {
                // IPv6 整段枚举只支持 /112 及更长（即最多 65536 个地址）：
                // 更短的网段地址空间太大，枚举没有意义。
                if (prefix_len < 112) {
                    printf("--full 对 IPv6 只支持 /112 及更长的前缀: %s\n", hostips.c_str());
                    return 1;
                }
                unsigned long long total = 1ULL << (128 - prefix_len);
                unsigned char base6[16];
                memcpy(base6, prefix, 16);
                for (int b = prefix_len; b < 128; ++b) {
                    base6[b / 8] &= (unsigned char)~(0x80 >> (b % 8));
                }
                for (unsigned long long k = 0; k < total; ++k) {
                    unsigned char a2[16];
                    memcpy(a2, base6, 16);
                    a2[15] = (unsigned char)(base6[15] + (k & 0xFF));
                    a2[14] = (unsigned char)(base6[14] + ((k >> 8) & 0xFF));
                    char ip_str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, a2, ip_str, sizeof(ip_str)) == NULL) {
                        snprintf(ip_str, sizeof(ip_str), "::");
                    }
                    ip_pool.push(TestTarget{std::string(ip_str), port});
                }
                ip_count = (int)total;
                printf("已完成IPv6整段枚举并压入IP池（栈），共 %d 个目标\n", ip_count);
            } else {
                for (int i = 0; i < ip_count; i++) {
                    char ip_str[INET6_ADDRSTRLEN];
                    generate_random_ipv6(prefix, prefix_len, ip_str, sizeof(ip_str));
                    ip_pool.push(TestTarget{std::string(ip_str), port}); // 压栈
                }
                printf("已完成IPv6地址生成并压入IP池（栈），共 %d 个目标\n", ip_count);
            }
        }
    } else {
        // Single host
        ip_pool.push(TestTarget{hostips, port});
    }

    // ====== Phase 2: Open CSV ======
    FILE* csv_file = fopen("rtts.csv", "w");
    if (csv_file == NULL) {
        perror("无法创建或打开rtts.csv文件");
        return 1;
    }
    // Write UTF-8 BOM to fix Chinese character encoding in Excel/other tools
    fprintf(csv_file, "\xEF\xBB\xBF");
#ifdef MAIN
    fprintf(csv_file, "ip,ip_with_brackets,ip_port_with_brackets,延迟\n");
#endif

    // ====== Phase 3: Threaded testing — 多线程并行从IP池pop测速 ======
    size_t num_targets = ip_pool.size();
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    if (num_threads > num_targets) num_threads = (unsigned int)num_targets;

    const char *proto_name = (protocol == PROTO_WG) ? "WireGuard"
                           : (protocol == PROTO_UDP) ? "UDP" : "TCP";
    printf("开始并行测速（%s）: IP池（栈）中有 %zu 个目标, %u 个线程\n",
           proto_name, num_targets, num_threads);
    if (protocol == PROTO_UDP || protocol == PROTO_WG) {
        printf("%s 载荷 %zu 字节, 超时预算 %.0f ms\n", proto_name,
               udp_payload.size(), budget_ms);
    }

    std::mutex pool_mutex;              // 保护IP池的并发pop（出栈锁）
    std::atomic<size_t> tested_count(0); // 已完成计数，仅用于进度显示
    std::mutex io_mutex;                // 保护终端/CSV输出

    // UDP 模式下 send() 永远拿到一个合法指针：空载荷时指向这个哑元
    const unsigned char *payload_ptr =
        udp_payload.empty() ? kEmptyUdpPayload : &udp_payload[0];
    size_t payload_len = udp_payload.size();

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (unsigned int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker_thread_func,
            std::ref(ip_pool), std::ref(pool_mutex), std::ref(tested_count),
            num_targets, csv_file, std::ref(io_mutex),
            protocol, payload_ptr, payload_len, budget_ms);
    }

    for (auto& t : threads) {
        t.join();
    }

    printf("所有测试完成，IP池剩余: %zu\n", ip_pool.size());
    fclose(csv_file);
    return 0;
}


#ifdef MAIN
int main(int argc, char *argv[]){
    char prog[] = " ";
    argv[0] = prog;
    return cidr_ping_main(argc, argv); // 传播返回码，参数错误时进程应以非 0 退出
}
#endif