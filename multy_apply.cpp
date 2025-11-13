#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
#include"cidr-ping.h"

int main(int argc, char* argv[]){
    /* cidrfile port num_of_cidr */
    
    if (argc < 4) {
        printf("用法: %s <cidr文件> <端口> <CIDR数量>\n", argv[0]);
        return 1;
    }
    
    FILE* file = fopen(argv[1], "r");
    if (file == NULL) {
        printf("无法打开文件: %s\n", argv[1]);
        return 1;
    }
    
    char line[46] = {0};
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = 0;
        // 创建参数字符串数组
        char* args[] = {
            "cidr-ping",     // 程序名
            line,            // CIDR行
            argv[2],         // 端口字符串
            argv[3],         // 数量字符串
            NULL
        };
        
        cidr_ping_main(4, args);
    }  
    
    fclose(file);
    return 0;
}