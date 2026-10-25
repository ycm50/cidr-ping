// tests/test_sort_rtts.cpp
//
// rtts-sort.h 的端到端测试：读 CSV（含转义字段 / 失败行 / NaN）→ 排序 → 写出。
// 只使用工作目录下的临时文件，不依赖网络。

#include "rtts-sort.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (cond) { ++g_pass; }                                         \
        else {                                                          \
            ++g_fail;                                                   \
            printf("   [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                               \
    } while (0)

#define CHECK_EQ(actual, expected)                                      \
    do {                                                                \
        long long a_ = (long long)(actual);                             \
        long long e_ = (long long)(expected);                           \
        if (a_ == e_) { ++g_pass; }                                     \
        else {                                                          \
            ++g_fail;                                                   \
            printf("   [FAIL] %s:%d: %s = %lld, 期望 %lld\n",           \
                   __FILE__, __LINE__, #actual, a_, e_);                \
        }                                                               \
    } while (0)

static void write_file(const char *path, const std::string &content) {
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    out.write(content.data(), (std::streamsize)content.size());
}

static std::string read_file(const char *path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    std::string s;
    if (!in) return s;
    std::string line;
    while (std::getline(in, line)) {
        s += line;
        s += "\n";
    }
    return s;
}

// 正常 CSV：表头 + 成功行 + WG 行 + 失败行 + NaN 行 + 负数行
static void test_load_sort_write() {
    printf("\n== load_csv / sort_rows / write_csv\n");

    const char *src = "rtts_test_in.csv";
    std::string content;
    content += "\xEF\xBB\xBF";
    content += "ip,ip_with_brackets,ip_port_with_brackets,延迟,detail\n";
    content += "10.0.0.3,[10.0.0.3],10.0.0.3:443,30.00,\n";
    content += "\"10.0.0.1,eu\",[10.0.0.1],10.0.0.1:443,10.50,\n";
    content += "10.0.0.2,[10.0.0.2],10.0.0.2:443,WG握手响应(0x02)@20.25,\n";
    content += "10.0.0.9,[10.0.0.9],10.0.0.9:443,连接失败,拒绝\n";
    content += "10.0.0.8,[10.0.0.8],10.0.0.8:443,nan,\n";
    content += "10.0.0.7,[10.0.0.7],10.0.0.7:443,-1,\n";
    write_file(src, content);

    std::vector<rtts::Row> rows;
    long skipped = 0;
    std::string header;
    bool header_seen = false;
    std::string err;

    long n = rtts::load_csv(src, rows, skipped, header, header_seen, err);
    CHECK_EQ(n, 3);            // 3 条可解析
    CHECK_EQ((int)rows.size(), 3);
    CHECK_EQ(skipped, 3);      // 连接失败 / nan / -1
    CHECK(header_seen);
    CHECK(header.find("ip_with_brackets") != std::string::npos);

    // 带逗号的字段必须完整保留
    bool found_comma_ip = false;
    for (size_t i = 0; i < rows.size(); ++i) {
        if (rows[i].ip == "10.0.0.1,eu") found_comma_ip = true;
    }
    CHECK(found_comma_ip);

    rtts::sort_rows(rows);
    CHECK(rows[0].rtt <= rows[1].rtt);
    CHECK(rows[1].rtt <= rows[2].rtt);
    CHECK_EQ((long long)(rows[0].rtt * 100.0 + 0.5), 1050); // 10.50
    CHECK_EQ((long long)(rows[2].rtt * 100.0 + 0.5), 3000); // 30.00

    const char *dst = "rtts_test_out.csv";
    CHECK(rtts::write_csv(dst, rows, header, header_seen, err));

    std::string out = read_file(dst);
    CHECK(out.find("ip_with_brackets") != std::string::npos);   // 表头保留
    CHECK(out.find("10.50") != std::string::npos);
    CHECK(out.find("10.0.0.3") != std::string::npos);

    // 输出必须仍可被自己解析回来（往返一致）
    std::vector<rtts::Row> rows2;
    long skipped2 = 0;
    std::string header2;
    bool header2_seen = false;
    CHECK_EQ(rtts::load_csv(dst, rows2, skipped2, header2, header2_seen, err), 3);
    CHECK_EQ(skipped2, 0);
    CHECK(header2_seen);
    CHECK_EQ((int)rows2.size(), 3);
    CHECK(rows2[0].ip == "10.0.0.1,eu");
}

// 无表头的 CSV（库模式输出）：第一行是数据，不能被当成表头丢掉
static void test_headerless() {
    printf("\n== 无表头 CSV\n");

    const char *src = "rtts_test_noheader.csv";
    std::string content;
    content += "\xEF\xBB\xBF";
    content += "192.0.2.1,192.0.2.1,192.0.2.1:80,5.00,\n";
    content += "192.0.2.2,192.0.2.2,192.0.2.2:80,1.00,\n";
    write_file(src, content);

    std::vector<rtts::Row> rows;
    long skipped = 0;
    std::string header;
    bool header_seen = false;
    std::string err;

    CHECK_EQ(rtts::load_csv(src, rows, skipped, header, header_seen, err), 2);
    CHECK(!header_seen);
    CHECK_EQ(skipped, 0);

    rtts::sort_rows(rows);
    CHECK(rows[0].ip == "192.0.2.2");
    CHECK(rows[1].ip == "192.0.2.1");

    // 无表头输入也要输出标准表头，保证下游按列名读取不会失败
    CHECK(rtts::write_csv("rtts_test_noheader_out.csv", rows, header, header_seen, err));
    std::string out = read_file("rtts_test_noheader_out.csv");
    CHECK(out.find("ip,ip_with_brackets") != std::string::npos);
}

static void test_missing_file() {
    printf("\n== 打不开的文件\n");

    std::vector<rtts::Row> rows;
    long skipped = 0;
    std::string header;
    bool header_seen = false;
    std::string err;

    CHECK_EQ(rtts::load_csv("no-such-file-xyz.csv", rows, skipped, header, header_seen, err), -1);
    CHECK(!err.empty());
    CHECK_EQ((int)rows.size(), 0);
}

int main() {
    printf("cidr-ping sort-rtts 测试\n");

    test_load_sort_write();
    test_headerless();
    test_missing_file();

    printf("\n----------------------------------------\n");
    printf("通过: %d, 失败: %d\n", g_pass, g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}