#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_LINE_LENGTH 256
#define MAX_COMMANDS 100
#define MAX_PATH_LENGTH 256

void extract_high_risk_commands(const char *filename, char commands[MAX_COMMANDS][MAX_LINE_LENGTH], int *command_count, char *log_path) {
    FILE *file = fopen(filename, "r");
    char log_error[256];
    if (!file) {
        sprintf(log_error,"Failed to open config file:[%s]",filename);
        perror(log_error);
        return;
    }

    char line[MAX_LINE_LENGTH];
    int in_commands_section = 0;
    *command_count = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        // 去掉行尾换行符
        line[strcspn(line, "\n")] = '\0';

        // 解析高风险命令部分
        if (strstr(line, "[HighRiskCommands]")) {
            in_commands_section = 1;
            continue;
        } else if (strstr(line, "[Logging]")) {
            in_commands_section = 0;
            continue;
        }

        if (in_commands_section && strstr(line, "commands = [")) {
            while (fgets(line, sizeof(line), file) != NULL) {
                line[strcspn(line, "\n")] = '\0';
                
                // 如果遇到 ] 或者空行停止读取
                if (strstr(line, "]") || strlen(line) == 0) {
                    break;
                }

                // 去掉可能的引号和空格
                char *start = strchr(line, '"');
                char *end = strrchr(line, '"');
                if (start && end && start != end) {
                    strncpy(commands[*command_count], start + 1, end - start - 1);
                    commands[*command_count][end - start - 1] = '\0'; // 添加字符串结束符
                    (*command_count)++;
                }
            }
        }

        // 解析日志路径
        if (strstr(line, "log_path =")) {
            sscanf(line, "log_path = \"%255[^\"]\"", log_path);
        }
    }

    fclose(file);
}

//清楚两边空格
void trim_spaces(char *str) {
    // 去除前导空格
    while (isspace((unsigned char)*str)) str++;
    
    // 去除尾部空格
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // 以'\0'结束字符串
    *(end + 1) = '\0';
}

void extract_value(const char *line, const char *prefix, char *value) {
    // 查找 prefix 的位置
    const char *pos = strstr(line, prefix);
    if (pos) {
        // 移动到 prefix 的结束后
        pos += strlen(prefix);
        
        // 找到下一个空格或字符串结束符
        const char *end = strpbrk(pos, " "); // 查找空格
        //char value[256]; // 假定最大值长度为 256
        if (end) {
            size_t len = end - pos; // 计算要复制的长度
            strncpy(value, pos, len);
            value[len] = '\0'; // 以 '\0' 结束字符串
        } else {
            strcpy(value, pos); // 直接复制到字符串结束
        }
        
        // 去掉值的前后空格
        trim_spaces(value);
        
        // 打印结果
        //printf("%s=%s\n", prefix, value);
    }
}
