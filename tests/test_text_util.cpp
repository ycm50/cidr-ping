// tests/test_text_util.cpp
//
// text-util.h 的纯文本工具测试：严格数值解析 + CSV 转义/解析。
// 不依赖网络、不依赖第三方框架，可单独运行也可由 ctest 驱动。

#include "text-util.h"

#include <cstdio>
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

static void test_parse_long_strict() {
    printf("\n== parse_long_strict\n");
    long v = 0;

    CHECK(parse_long_strict("443", 1, 65535, &v));
    CHECK_EQ(v, 443);

    CHECK(parse_long_strict("65535", 1, 65535, &v));
    CHECK_EQ(v, 65535);

    // 边界与符号
    CHECK(parse_long_strict("1", 1, 65535, &v));
    CHECK(!parse_long_strict("0", 1, 65535, &v));
    CHECK(!parse_long_strict("65536", 1, 65535, &v));
    CHECK(!parse_long_strict("-1", 1, 65535, &v));
    CHECK(parse_long_strict("+7", 1, 65535, &v));
    CHECK_EQ(v, 7);

    // 尾随垃圾、空白、空串、进制前缀一律拒绝
    CHECK(!parse_long_strict("443abc", 1, 65535, &v));
    CHECK(!parse_long_strict("443 ", 1, 65535, &v));
    CHECK(!parse_long_strict(" 443", 1, 65535, &v));
    CHECK(!parse_long_strict("0x10", 0, 100, &v));
    CHECK(!parse_long_strict("", 0, 100, &v));
    CHECK(!parse_long_strict("--5", -100, 100, &v));
    CHECK(!parse_long_strict("4.5", 0, 100, &v));

    // 溢出必须被挡住
    CHECK(!parse_long_strict("99999999999999999999999999", 0, 100000000L, &v));
}

static void test_parse_double_strict() {
    printf("\n== parse_double_strict\n");
    double d = 0.0;

    CHECK(parse_double_strict("1000", 1.0, 60000.0, &d));
    CHECK(d == 1000.0);

    CHECK(parse_double_strict("1.5", 1.0, 60000.0, &d));
    CHECK(d == 1.5);

    CHECK(!parse_double_strict("0", 1.0, 60000.0, &d));
    CHECK(!parse_double_strict("-5", 1.0, 60000.0, &d));
    CHECK(!parse_double_strict("60001", 1.0, 60000.0, &d));
    CHECK(!parse_double_strict("abc", 1.0, 60000.0, &d));
    CHECK(!parse_double_strict("1000ms", 1.0, 60000.0, &d));
    CHECK(!parse_double_strict("", 1.0, 60000.0, &d));
    // nan / inf 不能通过（它们会让超时计算变成未定义行为）
    CHECK(!parse_double_strict("nan", 0.0, 60000.0, &d));
    CHECK(!parse_double_strict("inf", 0.0, 60000.0, &d));
    CHECK(!parse_double_strict("-inf", 0.0, 60000.0, &d));
}

static void test_csv_escape() {
    printf("\n== csv_escape\n");

    CHECK(csv_escape("127.0.0.1") == "127.0.0.1");
    CHECK(csv_escape("addrinfo failed") == "addrinfo failed");
    CHECK(csv_escape("a,b") == "\"a,b\"");
    CHECK(csv_escape("say \"hi\"") == "\"say \"\"hi\"\"\"");
    CHECK(csv_escape("line1\nline2") == "\"line1\nline2\"");
    CHECK(csv_escape("") == "");
}

static void test_csv_split_line() {
    printf("\n== csv_split_line\n");
    std::vector<std::string> f;

    CHECK(csv_split_line("a,b,c", f));
    CHECK_EQ((int)f.size(), 3);
    CHECK(f[0] == "a" && f[1] == "b" && f[2] == "c");

    // 字段为空也要保留
    CHECK(csv_split_line("a,,c", f));
    CHECK_EQ((int)f.size(), 3);
    CHECK(f[1] == "");

    // 行尾空字段
    CHECK(csv_split_line("1,2,", f));
    CHECK_EQ((int)f.size(), 3);
    CHECK(f[2] == "");

    // 引号包裹的逗号
    CHECK(csv_split_line("\"10.0.0.1,eu\",12.5", f));
    CHECK_EQ((int)f.size(), 2);
    CHECK(f[0] == "10.0.0.1,eu");
    CHECK(f[1] == "12.5");

    // "" 转义成单个引号
    CHECK(csv_split_line("\"say \"\"hi\"\"\",ok", f));
    CHECK_EQ((int)f.size(), 2);
    CHECK(f[0] == "say \"hi\"");

    // 未闭合的引号必须报错，而不是静默解析出一堆垃圾
    CHECK(!csv_split_line("\"unterminated,1,2", f));
}

static void test_csv_parse_rtt() {
    printf("\n== csv_parse_rtt\n");
    double v = 0.0;

    CHECK(csv_parse_rtt("12.34", &v));
    CHECK(v == 12.34);

    CHECK(csv_parse_rtt("215.45", &v));
    CHECK(v == 215.45);

    // WG 状态列：取 @ 之后的数字
    CHECK(csv_parse_rtt("WG握手响应(0x02)@215.45", &v));
    CHECK(v == 215.45);

    CHECK(csv_parse_rtt("0", &v));
    CHECK(v == 0.0);

    // 失败行 / 非法值一律跳过
    CHECK(!csv_parse_rtt("连接失败", &v));
    CHECK(!csv_parse_rtt("UDP无响应", &v));
    CHECK(!csv_parse_rtt("", &v));
    CHECK(!csv_parse_rtt("nan", &v));
    CHECK(!csv_parse_rtt("inf", &v));
    CHECK(!csv_parse_rtt("-1", &v));
    CHECK(!csv_parse_rtt("12.34abc", &v));
    CHECK(!csv_parse_rtt("WG握手响应(0x02)@", &v));
}

int main() {
    printf("cidr-ping 文本工具测试\n");

    test_parse_long_strict();
    test_parse_double_strict();
    test_csv_escape();
    test_csv_split_line();
    test_csv_parse_rtt();

    printf("\n----------------------------------------\n");
    printf("通过: %d, 失败: %d\n", g_pass, g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}