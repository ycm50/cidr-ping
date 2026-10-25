// multy_apply.cpp —— 从文件逐行读取 CIDR，逐个扫描，并把结果合并成一份表
//
// 改动要点：
//   * 不再每次调用都覆盖 rtts.csv：每次运行先把上一轮的文件规整掉，
//     再把每个网段的结果用同一张表头合并到一个文件，最后输出汇总；
//   * 逐行严格解析：跳过空行与以 '#' 开头的注释行；
//   * 传播错误：某一段失败只记录并继续，但全部失败时以非 0 退出；
//   * 固定以 TCP 模式调用核心（与旧行为一致），但允许通过环境变量覆盖参数已无必要。

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "cidr-ping.h"

// 把 part 追加到 merged（不存在则创建并写入表头）
static bool append_without_header(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (in == NULL) return false;
    FILE *out = fopen(dst, "ab");
    if (out == NULL) { fclose(in); return false; }

    char line[8192];
    bool first = true;
    while (fgets(line, sizeof(line), in) != NULL) {
        if (first) {
            first = false;
            // 跳过 BOM
            char *p = line;
            if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) {
                p += 3;
            }
            // 跳过表头行
            if (strncmp(p, "ip,ip_with_brackets", 19) == 0) continue;
            fputs(p, out);
            continue;
        }
        fputs(line, out);
    }

    fclose(in);
    fclose(out);
    return true;
}

int main(int argc, char *argv[]) {
    /* cidrfile port num_of_cidr */

    if (argc < 4) {
        printf("用法: %s <cidr文件> <端口> <CIDR数量>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        printf("无法打开文件: %s\n", argv[1]);
        return 1;
    }

    // 汇总文件：有表头，然后逐个网段追加数据行
    const char *merged = "rtts_merged.csv";
    remove(merged);
    {
        FILE *m = fopen(merged, "wb");
        if (m == NULL) {
            printf("无法创建 %s\n", merged);
            fclose(file);
            return 1;
        }
        fprintf(m, "\xEF\xBB\xBF");
        fprintf(m, "ip,ip_with_brackets,ip_port_with_brackets,延迟,detail\n");
        fclose(m);
    }

    char line[512];
    int segments = 0;
    int failed = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = 0;

        // 去空白
        std::string cidr(line);
        size_t b = 0;
        while (b < cidr.size() && (cidr[b] == ' ' || cidr[b] == '\t')) ++b;
        size_t e = cidr.size();
        while (e > b && (cidr[e - 1] == ' ' || cidr[e - 1] == '\t')) --e;
        cidr = cidr.substr(b, e - b);

        if (cidr.empty() || cidr[0] == '#') continue; // 空行 / 注释

        ++segments;

        char prog[] = "cidr-ping";
        char *args[] = {
            prog,
            const_cast<char *>(cidr.c_str()),
            argv[2],
            argv[3],
            NULL
        };

        int rc = cidr_ping_main(4, args);
        if (rc != 0) {
            printf("网段 %s 测试失败（返回码 %d），继续下一个\n", cidr.c_str(), rc);
            ++failed;
            continue;
        }

        if (!append_without_header("rtts.csv", merged)) {
            printf("合并 %s 的结果失败\n", cidr.c_str());
            ++failed;
        }
    }

    fclose(file);

    printf("共处理 %d 个网段，失败 %d 个；合并结果: %s\n", segments, failed, merged);
    return (segments > 0 && failed == segments) ? 1 : 0;
}