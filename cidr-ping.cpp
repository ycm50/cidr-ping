#include "cidr-ping.h"

#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

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
        return -4;
    }

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[10];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        WSACleanup();
        return -1;
    }

    LARGE_INTEGER start_time, end_time, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start_time);

    SOCKET sockfd = INVALID_SOCKET;
    int connect_result = -1;

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
            freeaddrinfo(result);
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
                connect_result = -3; // timeout — 测试前已计时，超过1000ms终止
                break;
            }
            continue;
        }

        // Check SO_ERROR
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
            closesocket(sockfd);
            sockfd = INVALID_SOCKET;
            connect_result = -1;
            continue;
        }

        // Success!
        QueryPerformanceCounter(&end_time);
        *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;
        freeaddrinfo(result);
        return 0;
    }

    // All attempts failed
    QueryPerformanceCounter(&end_time);
    *delay_ms = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / (double)freq.QuadPart;

    if (sockfd != INVALID_SOCKET) closesocket(sockfd);
    freeaddrinfo(result);
    WSACleanup();
    return -3;
}

#else // POSIX

#include <fcntl.h>      // fcntl(), O_NONBLOCK

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
        return -1;
    }

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    int sockfd = -1;
    int connect_result = -1;

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
                connect_result = -3; // timeout — 测试前已计时，超过1000ms终止
                break;
            }
            continue;
        }

        // Check SO_ERROR
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            close(sockfd);
            sockfd = -1;
            connect_result = -1;
            continue;
        }

        // Success!
        gettimeofday(&end_time, NULL);
        *delay_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                    (end_time.tv_usec - start_time.tv_usec) / 1000.0;
        freeaddrinfo(result);
        return 0;
    }

    // All attempts failed
    gettimeofday(&end_time, NULL);
    *delay_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                (end_time.tv_usec - start_time.tv_usec) / 1000.0;

    if (sockfd >= 0) close(sockfd);
    freeaddrinfo(result);
    return -3;
}

#endif

// 显示结果
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

// Thread-safe test target — 测试前预先拟好测试列表
struct TestTarget {
    std::string ip_str;
    int port;
};

// Worker thread function — 通过原子索引安全地获取下一个目标并测试
static void worker_thread_func(
    const std::vector<TestTarget>& targets,
    std::atomic<size_t>& next_index,
    FILE* csv_file,
    std::mutex& io_mutex)
{
    while (true) {
        size_t idx = next_index.fetch_add(1, std::memory_order_relaxed);
        if (idx >= targets.size()) break;

        const TestTarget& target = targets[idx];

        // 每个独立线程在测试前计时（test_telnet_delay内部开始计时）
        double delay_ms;
        int result = test_telnet_delay(target.ip_str.c_str(), target.port, &delay_ms);

        // 加锁保证线程安全的I/O输出
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            printf("[%zu/%zu] ", idx + 1, targets.size());
            display_result(target.ip_str.c_str(), target.port, result, delay_ms, csv_file);
        }
    }
}

int cidr_ping_main(int argc, char *argv[]) {
    set_console_utf8();
    srand((unsigned int)time(NULL));

    // ====== Parse arguments ======
    std::string hostips;
    int port = 443;
    int ip_count = 10;

    if (argc >= 2) {
        hostips = argv[1];
        if (argc >= 3) {
            port = atoi(argv[2]);
            if (argc >= 4) {
                ip_count = atoi(argv[3]);
                if (ip_count <= 0) {
                    printf("生成IP的数量必须大于0\n");
                    return 1;
                }
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
        }

        printf("请输入生成IP的数量 (默认10): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL || buf[0] == '\n') {
            ip_count = 10;
        } else {
            ip_count = atoi(buf);
            if (ip_count <= 0) {
                printf("生成IP的数量必须大于0\n");
                return 1;
            }
        }
    }

    if (port <= 0 || port > 65535) {
        printf("端口必须是1-65535之间的数字\n");
        return 1;
    }

    // ====== Phase 1: Pre-generate all test targets ======
    // 在测试前先拟好完整的测试列表，保证所有IP在单线程中生成（rand()非线程安全）
    std::vector<TestTarget> targets;

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

            targets.reserve((size_t)ip_count);
            for (int i = 0; i < ip_count; i++) {
                char ip_str[INET_ADDRSTRLEN];
                generate_random_ipv4(ipv4_prefix_addr, ipv4_prefix_len, ip_str, sizeof(ip_str));
                targets.push_back({std::string(ip_str), port});
            }
            printf("已完成IPv4地址生成，共 %d 个目标\n", ip_count);
        } else {
            // IPv6 CIDR
            unsigned char prefix[16];
            int prefix_len;
            if (parse_ipv6_prefix(hostips.c_str(), prefix, &prefix_len) != 0) {
                printf("无效的IPv6网段格式: %s\n", hostips.c_str());
                return 1;
            }

            targets.reserve((size_t)ip_count);
            for (int i = 0; i < ip_count; i++) {
                char ip_str[INET6_ADDRSTRLEN];
                generate_random_ipv6(prefix, prefix_len, ip_str, sizeof(ip_str));
                targets.push_back({std::string(ip_str), port});
            }
            printf("已完成IPv6地址生成，共 %d 个目标\n", ip_count);
        }
    } else {
        // Single host
        targets.push_back({hostips, port});
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

    // ====== Phase 3: Threaded testing ======
    size_t num_targets = targets.size();
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    if (num_threads > num_targets) num_threads = (unsigned int)num_targets;

    printf("开始并发测试: %zu 个目标, %u 个线程\n", num_targets, num_threads);

    std::atomic<size_t> next_index(0);
    std::mutex io_mutex;

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (unsigned int i = 0; i < num_threads; i++) {
        threads.emplace_back(worker_thread_func,
            std::ref(targets), std::ref(next_index), csv_file, std::ref(io_mutex));
    }

    for (auto& t : threads) {
        t.join();
    }

    printf("所有测试完成\n");
    fclose(csv_file);
    return 0;
}


#ifdef MAIN
int main(int argc, char *argv[]){
    argv[0]=" ";
    cidr_ping_main( argc,  argv);
    return 0;
}
#endif