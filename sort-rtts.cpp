// sort-rtts.cpp —— 读取 rtts*.csv，按延迟升序输出到 rtts_sorted.csv
//
// 读写与排序逻辑在 rtts-sort.h（header-only），这里只负责命令行与汇总输出。
// 支持传入多个输入文件（便于把多个网段的结果合并排序）。

#include <iostream>
#include <string>
#include <vector>

#include "rtts-sort.h"

int main(int argc, char *argv[]) {
    std::vector<std::string> inputs;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != NULL && argv[i][0] != '\0') inputs.push_back(argv[i]);
    }
    if (inputs.empty()) inputs.push_back("rtts.csv");

    std::vector<rtts::Row> rows;
    long skipped = 0;
    std::string header;
    bool header_seen = false;
    long files_ok = 0;

    for (size_t i = 0; i < inputs.size(); ++i) {
        std::string err;
        long n = rtts::load_csv(inputs[i], rows, skipped, header, header_seen, err);
        if (n < 0) {
            std::cerr << err << std::endl;
            continue;
        }
        ++files_ok;
    }

    if (files_ok == 0) {
        std::cerr << "没有成功读取任何输入文件" << std::endl;
        return 1;
    }

    rtts::sort_rows(rows);

    std::string err;
    if (!rtts::write_csv("rtts_sorted.csv", rows, header, header_seen, err)) {
        std::cerr << err << std::endl;
        return 1;
    }

    std::cout << "已排序 " << rows.size() << " 行";
    if (skipped > 0) std::cout << "，跳过 " << skipped << " 行无法解析延迟的记录";
    std::cout << " -> rtts_sorted.csv" << std::endl;
    return 0;
}