
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <time.h>

#define DEBUG_FILE "/tmp/debug.log"

static void log_debug(const char *log_content) {
    FILE *log_file = fopen(DEBUG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL); // 获取当前时间的 Unix 时间戳
        fprintf(log_file, "time:%ld log_info: %s\n" , now, log_content);
    
        fclose(log_file);
    }
    else {
    
        perror("Failed to open debug log file");
    }
}


// 记录审计日志
static void log_audit(const char *command,const char *cmd_chain, const char *parent_command,const char *matched_command, int blocked,const char *LOG_FILE) {
    FILE *log_file = fopen(LOG_FILE, "a");
  
    if (log_file) {
        time_t now = time(NULL); // 获取当前时间的 Unix 时间戳
        if (blocked) {
            fprintf(log_file, "time:%ld,Blocked command: %s,parent_command: %s,cmd_chain: [%s],Matched pattern: %s\n", now, command,parent_command,cmd_chain, matched_command);
        } else {
            fprintf(log_file, "time:%ld,Executed command: %s,parent_command: %s,cmd_chain: [%s],No high-risk match\n", now, command,parent_command,cmd_chain);
        }
        fclose(log_file);
    } else {

        perror("Failed to open log file");
    }
}