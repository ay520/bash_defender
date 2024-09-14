#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include "get_cmdline_info.c"
#include "config_parse.c"
#include "log.c"

#define CONFIG_FILE "/etc/high_risk_commands_rules.conf"


#define MAX_LINE_LENGTH 256
#define MAX_COMMANDS 100
#define MAX_PATH_LENGTH 256

// 检查命令是否与高危命令匹配
static int check_command_chain(const char *parent_command, const char *child_command, char **matched_pattern , char commands[MAX_COMMANDS][MAX_LINE_LENGTH],const int command_count) {
    
    regex_t regex;
    int result = 0;
    char parent_pattern[1024]={0};
    char child_pattern[1024]={0};
    char mode_pattern[1024]={0};

    for(int i = 0; i < command_count; i++){
        // 检查父进程和子进程命令
        if (strstr(commands[i], "PARENT:") && strstr(commands[i], "CHILD:")) {
            // 从行中提取父进程和子进程命令
            extract_value(commands[i], "PARENT:",parent_pattern);
            extract_value(commands[i], "CHILD:",child_pattern);
            extract_value(commands[i], "MODE:",mode_pattern);


            if (regcomp(&regex, parent_pattern, REG_EXTENDED) == 0) {
                if (regexec(&regex, parent_command, 0, NULL, 0) == 0) {
                    // 只有父进程匹配的情况下才检查子进程
                    regfree(&regex);
                    if (regcomp(&regex, child_pattern, REG_EXTENDED) == 0) {
                        if (regexec(&regex, child_command, 0, NULL, 0) == 0) {
                            result = 1; // 找到匹配
                            *matched_pattern = strdup(commands[i]); // 保存匹配的规则
                            regfree(&regex);
                            break;
                        }
                        regfree(&regex);
                    }
                } else {
                    regfree(&regex);
                }
            }
        }
    }
    
    if(strcmp(mode_pattern,"watch")==0){
        return 2; //返回观察模式值
    }

    return result;

    
}



// 自定义 execve 函数
typedef int (*orig_execve_type)(const char *filename, char *const argv[], char *const envp[]);

int execve(const char *filename, char *const argv[], char *const envp[]) {

    char    strCmdChain[102400] = {0};
    char    *cmdline=NULL;
    int     cmd_len=0;
    //定义cmdchain 结构体用于存放信息
    cmd_chain_struct chain_struct_info;
    memset(&chain_struct_info,0,sizeof(chain_struct_info));


    get_cmd_chain(getpid(),&chain_struct_info);
    
    //获取系统启动时间，用于后续计算进程启动时间
    long int boot_time=get_system_boot_time();
    int chain_len=0;
    char progname[1024]={0};
    sprintf(progname,"%s",filename);
    
    //获取 argv 内容 
    for(int i=0;argv[i]!=NULL;i++){
     cmd_len+=strlen(argv[i])+1; 
    }

    cmdline=malloc(cmd_len+1);
    memset(cmdline,0,cmd_len+1);
    for (int i=0,n=0;argv[i]!=NULL;i++){
        if (n >=cmd_len) {
            break;
        }
        n += snprintf(cmdline+n,cmd_len-n, "%s", argv[i]);
        if (n >=cmd_len) {
            break;
        }
        cmdline[n] = ' ';
        n++;
    }

    // 获取父进程信息，为后续识别用
    char parent_command[1024];
    sprintf(parent_command, "%s", chain_struct_info.arr_cmdline[1]); // 假设第一个是父进程

    for(int i=0;i<100;i++){
        if(NULL==chain_struct_info.arr_cmdline[i]){
            break;
        }

        if (i != 0) {
            chain_len+=snprintf(strCmdChain + chain_len, 102400-chain_len, ",");
        }

        if(102400-chain_len>0){
            chain_len+=snprintf(strCmdChain+chain_len,102400-chain_len,
            "{\"pid\":%d,\"cmdline\":\"%s\",\"proc_path\":\"%s\",\"start_time\":%lld}",
            chain_struct_info.array_pids[i],
            i==0?cmdline:chain_struct_info.arr_cmdline[i], //当进程被拦截时，不能直接通过读取/proc/stat获取信息，只能通过传入的函数参数获取
            i==0?progname:chain_struct_info.arr_proc_path[i],
            boot_time+chain_struct_info.start_time[i]);
        }
        //释放内存
        if(NULL!=chain_struct_info.arr_cmdline[i]){
	    //printf("cmdline free,address:%u\n",chain_struct_info.arr_cmdline[i]);
            free(chain_struct_info.arr_cmdline[i]);
        }
        if(NULL!=chain_struct_info.arr_proc_path[i]){
	    //printf("proc path free,address:%u\n",chain_struct_info.arr_proc_path[i]);
            free(chain_struct_info.arr_proc_path[i]);
        }
    }
 

        char *matched_pattern = NULL;
        int blocked_status = 0;
        int result=0;

        char commands[MAX_COMMANDS][MAX_LINE_LENGTH];
        int command_count = 0;
        char log_path[MAX_PATH_LENGTH];
        extract_high_risk_commands(CONFIG_FILE, commands, &command_count, log_path);
        
        result=check_command_chain(parent_command, cmdline, &matched_pattern,commands,command_count);
        // 检查命令是否匹配高危规则  
        if (result==1) {
            blocked_status=1;
            log_audit(cmdline,strCmdChain,parent_command, matched_pattern, blocked_status,log_path); // 记录阻止的命令
            free(matched_pattern); // 释放匹配的规则
            errno = EACCES; // 设置 errno 为 权限拒绝
            return -1; // 阻止执行
        }else if (result==2){
            blocked_status=1;
            log_audit(cmdline,strCmdChain,parent_command, matched_pattern, blocked_status,log_path); // 记录高危命令,单不拦截
            free(matched_pattern); // 释放匹配的规则
        }
         else {
            log_audit(cmdline,strCmdChain,parent_command, NULL, blocked_status,log_path); // 记录未命中高危命令
        }


  
    free(cmdline);
    // printf("Cmd_Chain:[%s]\n",strCmdChain);

    orig_execve_type orig_execve;
    orig_execve = (orig_execve_type)dlsym(RTLD_NEXT, "execve");
    return orig_execve(filename, argv, envp);
}

/*

int main()
{

  char commands[MAX_COMMANDS][MAX_LINE_LENGTH];
  int command_count = 0;
  char log_path[MAX_PATH_LENGTH];


    char parent_pattern[1024]={0};
    char child_pattern[1024]={0};
    char mode_pattern[1024]={0};

  extract_high_risk_commands(CONFIG_FILE, commands, &command_count, log_path);
  for (int i = 0; i < command_count; i++) {
    if (strstr(commands[i], "PARENT:") && strstr(commands[i], "CHILD:")) {
            // 从行中提取父进程和子进程命令
            extract_value(commands[i], "PARENT:",parent_pattern);
            extract_value(commands[i], "CHILD:",child_pattern);
            extract_value(commands[i], "MODE:",mode_pattern);
    }
    printf("parent:%s,child:%s,mode:%s\n",parent_pattern,child_pattern,mode_pattern);

  }

}
*/