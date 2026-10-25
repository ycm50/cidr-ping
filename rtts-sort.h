// rtts-sort.h —— rtts.csv 的读取 / 排序 / 写出（header-only，便于单元测试）
//
// 规则：
//   * CSV 字段按 RFC 4180 解析，字段内的逗号/引号不会破坏列结构；
//   * 延迟列只接受「完整消费的有限非负数」，失败行跳过并计数；
//   * 表头按内容识别（而不是按行号），因此库模式产出的无表头 CSV 不会丢第一行；
//   * 输出统一 5 列：ip,ip_with_brackets,ip_port_with_brackets,延迟,detail。

#ifndef CIDR_PING_RTTS_SORT_H
#define CIDR_PING_RTTS_SORT_H

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "text-util.h"

namespace rtts {

struct Row {
    std::string ip;
    std::string ip_with_brackets;
    std::string ip_port_with_brackets;
    double rtt;
    std::string detail;
};

inline void strip_bom(std::string &s) {
    if (s.size() >= 3 &&
        (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB && (unsigned char)s[2] == 0xBF) {
        s.erase(0, 3);
    }
}

// 读取一个 CSV；返回读到的数据行数，-1 表示文件打不开（err 里是原因）。
inline long load_csv(const std::string &path,
                     std::vector<Row> &rows,
                     long &skipped,
                     std::string &header,
                     bool &header_seen,
                     std::string &err) {
    std::ifstream in(path.c_str(), std::ios::in | std::ios::binary);
    if (!in) {
        err = "无法打开: " + path;
        return -1;
    }

    std::string line;
    long data_rows = 0;
    bool first_line = true;

    while (std::getline(in, line)) {
        if (!line.empty() && line[line.size() - 1] == '\r') line.erase(line.size() - 1);
        if (first_line) {
            strip_bom(line);
            first_line = false;
        }
        if (line.empty()) continue;

        std::vector<std::string> fields;
        if (!csv_split_line(line, fields)) {
            ++skipped;
            continue;
        }

        // 表头按内容识别：第一列 ip、第二列 ip_with_brackets
        if (fields.size() >= 2 && fields[0] == "ip" && fields[1] == "ip_with_brackets") {
            if (!header_seen) {
                header = line;
                header_seen = true;
            }
            continue;
        }

        if (fields.size() < 4) {
            ++skipped;
            continue;
        }

        double rtt = 0.0;
        if (!csv_parse_rtt(fields[3], &rtt)) {
            ++skipped;
            continue;
        }

        Row row;
        row.ip = fields[0];
        row.ip_with_brackets = fields[1];
        row.ip_port_with_brackets = fields[2];
        row.rtt = rtt;
        row.detail = (fields.size() >= 5) ? fields[4] : std::string();
        rows.push_back(row);
        ++data_rows;
    }

    return data_rows;
}

inline void sort_rows(std::vector<Row> &rows) {
    std::stable_sort(rows.begin(), rows.end(),
                     [](const Row &a, const Row &b) { return a.rtt < b.rtt; });
}

inline bool write_csv(const std::string &path,
                      const std::vector<Row> &rows,
                      const std::string &header,
                      bool header_seen,
                      std::string &err) {
    std::ofstream out(path.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "无法写入: " + path;
        return false;
    }

    out << "\xEF\xBB\xBF";
    if (header_seen) {
        // header 本身就是一条合法的 CSV 行（读入时已去掉 BOM），不能整体再转义一次，
        // 否则会被包成一个字段，导致下次读回来时识别不到表头。
        out << header << "\n";
    } else {
        out << "ip,ip_with_brackets,ip_port_with_brackets,延迟,detail\n";
    }

    for (size_t i = 0; i < rows.size(); ++i) {
        char num[32];
        std::snprintf(num, sizeof(num), "%.2f", rows[i].rtt);
        out << csv_escape(rows[i].ip) << ","
            << csv_escape(rows[i].ip_with_brackets) << ","
            << csv_escape(rows[i].ip_port_with_brackets) << ","
            << num << ","
            << csv_escape(rows[i].detail) << "\n";
    }

    out.flush();
    return out.good();
}

} // namespace rtts

#endif // CIDR_PING_RTTS_SORT_H
