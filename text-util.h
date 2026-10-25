// text-util.h —— 与平台无关的小工具：严格数值解析 + CSV 转义/解析。
//
// 单独抽出来是为了让 cidr-ping 与 sort-rtts 共用同一套规则，并且能被测试
// 直接 include 覆盖（不依赖任何第三方框架）。

#ifndef CIDR_PING_TEXT_UTIL_H
#define CIDR_PING_TEXT_UTIL_H

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// 严格解析十进制整数：整串必须被完整消费（不允许前后空白、0x 前缀、
// 尾随垃圾），且结果必须落在 [min_v, max_v] 内。溢出返回 false。
inline bool parse_long_strict(const char *s, long min_v, long max_v, long *out) {
    if (s == NULL || out == NULL || *s == '\0') return false;

    const char *p = s;
    if (*p == '+' || *p == '-') ++p;
    if (*p == '\0') return false;
    for (; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return false;
    }

    errno = 0;
    char *end = NULL;
    long v = std::strtol(s, &end, 10);
    if (end == s || *end != '\0') return false;
    if (errno == ERANGE) return false;
    if (v < min_v || v > max_v) return false;

    *out = v;
    return true;
}

// 严格解析浮点数：整串必须被完整消费，必须有限，且落在 [min_v, max_v]。
inline bool parse_double_strict(const char *s, double min_v, double max_v, double *out) {
    if (s == NULL || out == NULL || *s == '\0') return false;
    if (*s == ' ' || *s == '\t') return false;

    errno = 0;
    char *end = NULL;
    double v = std::strtod(s, &end);
    if (end == s || *end != '\0') return false;
    if (errno == ERANGE) return false;
    if (!std::isfinite(v)) return false;
    if (v < min_v || v > max_v) return false;

    *out = v;
    return true;
}

// CSV 字段转义：字段含逗号/引号/CR/LF 时整体加双引号，内部引号翻倍。
inline std::string csv_escape(const std::string &field) {
    bool need = false;
    for (size_t i = 0; i < field.size(); ++i) {
        char c = field[i];
        if (c == ',' || c == '"' || c == '\r' || c == '\n') { need = true; break; }
    }
    if (!need) return field;

    std::string out;
    out.reserve(field.size() + 8);
    out.push_back('"');
    for (size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '"') out.push_back('"');
        out.push_back(field[i]);
    }
    out.push_back('"');
    return out;
}

// 按 RFC 4180 拆分一行 CSV（支持双引号包裹、"" 转义、字段内逗号）。
// 引号未闭合时返回 false，fields 内容未定义。
inline bool csv_split_line(const std::string &line, std::vector<std::string> &fields) {
    fields.clear();

    std::string cur;
    bool in_quotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push_back(c);
            }
        } else if (c == '"' && cur.empty()) {
            in_quotes = true;
        } else if (c == ',') {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }

    if (in_quotes) return false;
    fields.push_back(cur);
    return true;
}

// 从「延迟」列取毫秒值：
//   "12.34"                        -> true, 12.34
//   "WG握手响应(0x02)@215.45"       -> true, 215.45
//   "连接失败" / "" / "nan" / "-1"  -> false
// 只接受有限的非负数值；带 @ 的格式取 @ 之后的部分（兼容 WG 状态列）。
inline bool csv_parse_rtt(const std::string &field, double *out) {
    size_t at = field.rfind('@');
    std::string num = (at == std::string::npos) ? field : field.substr(at + 1);

    size_t b = 0;
    size_t e = num.size();
    while (b < e && (num[b] == ' ' || num[b] == '\t')) ++b;
    while (e > b && (num[e - 1] == ' ' || num[e - 1] == '\t' || num[e - 1] == '\r')) --e;
    num = num.substr(b, e - b);

    if (num.empty()) return false;

    double v = 0.0;
    // 上限 1e12 ms 只是用来挡住 inf/荒唐值，不限制正常延迟。
    if (!parse_double_strict(num.c_str(), 0.0, 1.0e12, &v)) return false;
    if (out != NULL) *out = v;
    return true;
}

#endif // CIDR_PING_TEXT_UTIL_H
