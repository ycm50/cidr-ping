#ifndef CIDR_PING_H
#define CIDR_PING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stddef.h>



#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else // POSIX
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#if defined(_WIN32) && defined(CIDR_PING_SHARED)
    #ifdef CIDR_PING_EXPORTS
        #define CIDR_PING_API __declspec(dllexport)
    #else
        #define CIDR_PING_API __declspec(dllimport)
    #endif
#elif defined(__GNUC__) && defined(CIDR_PING_SHARED)
    #define CIDR_PING_API __attribute__((visibility("default")))
#else
    #define CIDR_PING_API
#endif

// ===== test_*_delay() 的返回码 =====
#define CP_OK               0    // 成功，*delay_ms 有效
#define CP_ERR_RESOLVE     (-1)  // 域名/IP 解析失败
#define CP_ERR_SOCKET      (-2)  // 创建 socket 失败
#define CP_ERR_CONNECT     (-3)  // TCP 连接失败 / UDP 发送失败
#define CP_ERR_WINSOCK     (-4)  // WSAStartup 失败（仅 Windows）
#define CP_ERR_UDP_TIMEOUT (-5)  // UDP 在超时预算内一个回包都没收到
#define CP_ERR_UDP_ICMP    (-6)  // UDP 收到 ICMP 端口不可达：主机在线，但该端口无 UDP 服务
#define CP_ERR_TIMEOUT     (-7)  // 总预算耗尽（连接阶段超时）
#define CP_ERR_NO_ADDR     (-8)  // 解析成功但没有任何可用地址
#define CP_ERR_WG_NOT_WG   (-9)  // WG 模式收到回包，但它不满足 WireGuard 报文结构

// 总等待预算：UDP/WG 由 --udp-timeout 决定，TCP 使用这个默认值。
// 计时口径是「整个目标（含 DNS 解析与所有地址尝试）」的总预算。
#define CP_DEFAULT_CONNECT_TIMEOUT_MS 1000.0

#ifdef __cplusplus
extern "C" {
#endif
CIDR_PING_API int cidr_ping_main(int argc, char *argv[]);

// 供测试与 sort-rtts 复用的小接口（实现都在 cidr-ping.cpp / text-util.h）
CIDR_PING_API int  parse_ipv4_prefix(const char *prefix_str, unsigned int *ipv4_addr, int *prefix_len);
CIDR_PING_API int  parse_ipv6_prefix(const char *prefix_str, unsigned char *prefix, int *prefix_len);
CIDR_PING_API void generate_random_ipv4(unsigned int ipv4_addr, int prefix_len, char *output, size_t output_size);
CIDR_PING_API void generate_random_ipv6(const unsigned char *prefix, int prefix_len, char *output, size_t output_size);
CIDR_PING_API int  test_telnet_delay(const char *hostname, int port, double *delay_ms);
CIDR_PING_API int  test_udp_delay(const char *hostname, int port, const unsigned char *payload,
                                  size_t payload_len, double *delay_ms,
                                  unsigned char *resp_type, double budget_ms);
CIDR_PING_API int  test_target_delay(const char *hostname, int port, int protocol,
                                     const unsigned char *udp_payload, size_t udp_payload_len,
                                     double *delay_ms, unsigned char *resp_type, double budget_ms);

// 把目标渲染成 host / host:port 两种写法（IPv6 加方括号）。
// 只有「确实是 IPv6 字面量」才加方括号；主机名不会因为含 ':' 被误判。
CIDR_PING_API void cp_format_target(const char *target, int port,
                                    char *host_out, size_t host_size,
                                    char *hostport_out, size_t hostport_size);

// 把返回码 / WireGuard 回包类型渲染成 CSV 的状态列文本与终端提示。
// resp_type 仅在 CP_OK 且 protocol 为 WireGuard 时使用。
CIDR_PING_API void cp_status_text(int protocol, int result, int resp_type,
                                  char *status, size_t status_size,
                                  char *detail, size_t detail_size);
#ifdef __cplusplus
}
#endif

#endif // CIDR_PING_H