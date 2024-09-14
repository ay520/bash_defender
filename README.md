# bash_defender
对bash命令进行审计，对高危命令进行拦截

通过 LD_PRELOAD 实现对bash命令以及bash命令启动的进程进行日志审计，以及高危命令的识别和拦截

1、将配置文件 high_risk_commands_rules.conf 保存至 /etc/high_risk_commands_rules.conf
  此配置文件是拦截规则配置
  PARENT: 识别父进程，通过正则匹配
  CHILD:  识别子进程，通过正则匹配
  MODE:   watch 观察模式
          drop  拦截模式

  当满足 PARENT 规则 且 满足 CHILD 规则时，执行 拦截或者观察

  相关的日志保存在路径 log_path 参数，/var/log/high_risk_commands.log

2、配置 /etc/environment
  LD_PRELOAD="/path/to/libexecve_filter.so"


3、后续新启动的bash以及通过bash命令启动的进程均会生效

4、应急恢复：如果出现不符合预期情况下，可以直接删除配置文件或者删除libexecve_filter.so或者清理environment配置，并重启服务器
           或者连上ssh后， 输入 unset LD_PRELOAD [回车]  再输入 bash 进入新的bash
