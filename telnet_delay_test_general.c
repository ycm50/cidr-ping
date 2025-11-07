#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

// Set console output to UTF-8 to fix encoding issues
void set_console_utf8() {
    SetConsoleOutputCP(65001); // Set output code page to UTF-8
    SetConsoleCP(65001);       // Set input code page to UTF-8
}

// Function to test telnet delay
int test_telnet_delay(const char *hostname, int port, double *delay_ms) {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -4; // Failed to initialize Winsock
    }
    
    // 设置地址信息
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // 允许IPv4或IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP连接
    
    // 将端口转换为字符串
    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    // 获取地址信息
    int getaddrinfo_result = getaddrinfo(hostname, port_str, &hints, &result);
    if (getaddrinfo_result != 0) {
        WSACleanup();
        return -1; // Failed to get host info
    }
    
    // 创建socket并尝试连接
    SOCKET sockfd = INVALID_SOCKET;
    struct addrinfo *ptr = NULL;
    int connect_result = -1;
    
    // 记录连接开始时间
    LARGE_INTEGER start_time, end_time, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_time);
    
    // 尝试连接到获取的每个地址，直到成功
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // 创建socket
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == INVALID_SOCKET) {
            continue;
        }
        
        // 连接到服务器
        connect_result = connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (connect_result != SOCKET_ERROR) {
            break; // 连接成功
        }
        
        // 连接失败，关闭socket并尝试下一个地址
        closesocket(sockfd);
        sockfd = INVALID_SOCKET;
    }
    
    // 记录连接结束时间
    QueryPerformanceCounter(&end_time);
    
    // 释放地址信息
    freeaddrinfo(result);
    
    // 如果socket有效，关闭它
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    
    WSACleanup();
    
    if (connect_result == SOCKET_ERROR) {
        return -3; // Connection failed
    }
    
    // 计算延迟（毫秒）
    *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)frequency.QuadPart;
    
    return 0; // Success
}

#else // POSIX
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

// Placeholder for Windows-specific function
void set_console_utf8() {
    // Not needed for POSIX systems
}

// Function to test telnet delay for POSIX systems
int test_telnet_delay(const char *hostname, int port, double *delay_ms) {
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int getaddrinfo_result = getaddrinfo(hostname, port_str, &hints, &result);
    if (getaddrinfo_result != 0) {
        return -1; // Failed to get host info
    }

    int sockfd = -1;
    struct addrinfo *ptr = NULL;
    int connect_result = -1;

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        connect_result = connect(sockfd, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (connect_result != -1) {
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    gettimeofday(&end_time, NULL);

    freeaddrinfo(result);

    if (sockfd != -1) {
        close(sockfd);
    }

    if (connect_result == -1) {
        return -3; // Connection failed
    }

    *delay_ms = (double)(end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                (double)(end_time.tv_usec - start_time.tv_usec) / 1000.0;

    return 0; // Success
}
#endif

// Display test results
void display_result(const char *hostname, int port, int result, double delay_ms, FILE *csv_file) {
    char formatted_host_port[NI_MAXHOST + 10]; // Enough space for IPv6 + port
    char formatted_host[NI_MAXHOST];

    if (strchr(hostname, ':') != NULL) { // Likely IPv6
        snprintf(formatted_host_port, sizeof(formatted_host_port), "[%s]:%d", hostname, port);
        snprintf(formatted_host, sizeof(formatted_host), "[%s]", hostname);
    } else { // Likely IPv4
        snprintf(formatted_host_port, sizeof(formatted_host_port), "%s:%d", hostname, port);
        snprintf(formatted_host, sizeof(formatted_host), "%s", hostname);
    }

    switch (result) {
        case 0: // Success
            printf("连接成功，延迟: %.2f ms\n", delay_ms);
            fprintf(csv_file, "%s,%s,%s,%.2f\n", hostname, formatted_host, formatted_host_port, delay_ms);
            break;
        case -1: // Failed to get host info
            printf("无法解析主机名: %s\n", hostname);
            fprintf(csv_file, "%s,%s,%s,无法解析主机名\n", hostname, formatted_host, formatted_host_port);
            break;
        case -2: // Failed to create socket (This error code is not used in the general version, but kept for consistency)
            printf("创建socket失败\n");
            fprintf(csv_file, "%s,%s,%s,创建socket失败\n", hostname, formatted_host, formatted_host_port);
            break;
        case -3: // Connection failed
            printf("连接到 %s:%d 失败\n", hostname, port);
            fprintf(csv_file, "%s,%s,%s,连接失败\n", hostname, formatted_host, formatted_host_port);
            break;
        case -4: // Failed to initialize Winsock (Windows-specific, but kept for consistency)
            printf("初始化Winsock失败\n");
            fprintf(csv_file, "%s,%s,%s,初始化Winsock失败\n", hostname, formatted_host, formatted_host_port);
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
    unsigned int mask = 0xFFFFFFFF << (32 - prefix_len);
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

int main(int argc, char *argv[]) {
    // 设置控制台为UTF-8编码
    set_console_utf8();
    
    // 初始化随机数生成器
    srand((unsigned int)time(NULL));

    FILE *csv_file = NULL;
    csv_file = fopen("rtts.csv", "w");
    if (csv_file == NULL) {
        perror("无法创建或打开rtts.csv文件");
        return 1;
    }
    fprintf(csv_file, "ip,ip_with_brackets,ip_port_with_brackets,延迟\n");
    
    char hostips[256];
    int port;
    int ip_count = 100; // 默认生成100个IP
    
    // 检查命令行参数
    if (argc == 2) {
        strncpy(hostips, argv[1], sizeof(hostips) - 1);
        hostips[sizeof(hostips) - 1] = '\0';
        
        if (argc >= 3) {
            port = atoi(argv[2]);
            if (argc == 4) {
                ip_count = atoi(argv[3]);
                if (ip_count <= 0) {
                    printf("生成IP的数量必须大于0\n");
                    return 1;
                }
            }
        } else {
            port = 443; // 默认端口
        }
    } else {
        printf("请输入主机名或IPv6网段(格式如2400:cb00:2049::/48): ");
        if (fgets(hostips, sizeof(hostips), stdin) == NULL) {
            printf("输入错误\n");
            return 1;
        }
        
        // 移除换行符
        size_t len = strlen(hostips);
        if (len > 0 && hostips[len-1] == '\n') {
            hostips[len-1] = '\0';
        }
        
        printf("请输入端口号 (默认443): ");
        char port_str[10];
        if (fgets(port_str, sizeof(port_str), stdin) == NULL || port_str[0] == '\n') {
            port = 443; // 默认端口
        } else {
            port = atoi(port_str);
        }
        
        printf("请输入生成IP的数量 (默认100): ");
        char count_str[10];
        if (fgets(count_str, sizeof(count_str), stdin) == NULL || count_str[0] == '\n') {
            ip_count = 100; // 默认100个IP
        } else {
            ip_count = atoi(count_str);
            if (ip_count <= 0) {
                printf("生成IP的数量必须大于0\n");
                return 1;
            }
        }
    }
    
    // 验证端口号
    if (port <= 0 || port > 65535) {
        printf("端口必须是1-65535之间的数字\n");
        return 1;
    }
    
    // 检查是否是IPv6网段格式
    char *slash_pos = strchr(hostips, '/');
    if (slash_pos != NULL) {
        // 检查是否是IPv4网段格式
        if (strchr(hostips, '.') != NULL) {
            // 是IPv4网段，生成随机IP
            unsigned int ipv4_prefix_addr;
            int ipv4_prefix_len;
            char random_ipv4[INET_ADDRSTRLEN];

            if (parse_ipv4_prefix(hostips, &ipv4_prefix_addr, &ipv4_prefix_len) != 0) {
                printf("无效的IPv4网段格式: %s\n", hostips);
                return 1;
            }

            for (int i = 0; i < ip_count; i++) {
                generate_random_ipv4(ipv4_prefix_addr, ipv4_prefix_len, random_ipv4, sizeof(random_ipv4));
                printf("生成的随机IPv4地址: %s\n", random_ipv4);

                // 测试连接
                double delay_ms;
                int result = test_telnet_delay(random_ipv4, port, &delay_ms);

                // 显示结果
                display_result(random_ipv4, port, result, delay_ms, csv_file);
            }
        } else {
            // 是IPv6网段，生成随机IP
            unsigned char prefix[16];
            int prefix_len;
            char random_ip[INET6_ADDRSTRLEN];
            
            if (parse_ipv6_prefix(hostips, prefix, &prefix_len) != 0) {
                printf("无效的IPv6网段格式: %s\n", hostips);
                return 1;
            }
            
            for (int i = 0; i < ip_count; i++) {
                generate_random_ipv6(prefix, prefix_len, random_ip, sizeof(random_ip));
                printf("生成的随机IPv6地址: %s\n", random_ip);
                
                // 测试连接
                double delay_ms;
                int result = test_telnet_delay(random_ip, port, &delay_ms);
                
                // 显示结果
                display_result(random_ip, port, result, delay_ms, csv_file);
            }
        }
    } else {
        // 普通主机名或IP地址
        double delay_ms;
        int result = test_telnet_delay(hostips, port, &delay_ms);
        
        // 显示结果
        display_result(hostips, port, result, delay_ms, csv_file);
    }
    
    fclose(csv_file);
    return 0;
}