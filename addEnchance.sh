#!/bin/bash
sleep 3s
 #OS_Linux_1 查看所有用户
echo "OS_Linux_1 查看所有用户";
uid_min=`(egrep -v ^# /etc/login.defs |egrep "^UID_MIN"|awk '($1="UID_MIN"){print $2}')` 
uid_max=`(egrep -v ^# /etc/login.defs |egrep "^UID_MAX"|awk '($1="UID_MAX"){print $2}')` 
egrep -v "oracle|sybase|postgres|informix" /etc/passwd|awk -F: '($3>='$uid_min' && $3<='$uid_max') {print $1":"$3}' 
echo "result="`egrep -v "oracle|sybase|postgres|informix" /etc/passwd|awk -F: '($3>='$uid_min' && $3<='$uid_max') {print $1":"$3}'|wc -l`

sleep 3s
 #OS_Linux_2 限制root用户远程登录-telnet
flag=0
telnetStatus=$((`systemctl status telnet.socket |grep "listening"|wc -l`+`service telnet status|grep "listening"|wc -l`)) 
if [ "$telnetStatus" -eq 0 ];
 then flag=0;
else 
#ADD1 追加对pam.d/login内有无pam_securetty使用的查看与修补
  login=`cat /etc/pam.d/login|egrep -v "^#"|egrep -i 'auth.*pam_securetty.so'|wc -l`;
  if [ "$login" -eq 0 ];then echo "auth  required  pam_securetty.so">>/etc/pam.d/login ;((flag++));fi
  if [ -f /etc/securetty ];then
   if [ `cat /etc/securetty|grep "pts/*"|wc -l` -gt 0 ];
    then ((flag++));
     sed -i '/pts.*/d' /etc/securetty;fi;
  else ((flag++));
   echo "tty1
tty2
tty3
tty4
tty5
tty6
tty7
tty8
tty9">>/etc/securetty;
  fi;
fi;
if [ "$flag" -ne 0 ];then echo "OS_Linux_2 限制root用户远程登录-telnet不合规";
else echo "OS_Linux_2 限制root用户远程登录-telnet合规";fi;
   

sleep 3s
 #OS_Linux_3 限制root用户远程登录-ssh

flag=0 ;
permitR=`egrep -v "^[[:space:]]*#" /etc/ssh/sshd_config|egrep -i "PermitRootLogin (no)|(without-password)|(prohibit-password)|(forced-commands-only)" --color=never`
if [ -n "$permitR" ];
  then ((flag++)); 
   else 
    permitR=`egrep -v "^[[:space:]]*#" /etc/ssh/sshd_config|egrep -i 'PermitRootLogin.*'`
	if [ -n "$permitR" ];
	 then sed -i "s/$permitR/PermitRootLogin no/g" /etc/ssh/sshd_config;
	 else echo "PermitRootLogin no">>/etc/ssh/sshd_config;fi;
  fi 
permitR=`egrep  -v "^[[:space:]]*#" /etc/ssh/sshd_config|egrep -i "^[[:space:]]*protocol[[:space:]]*2|^[[:space:]]*Protocol[[:space:]]*2" --color=never`
if  [ -n "$permitR" ];
  then ((flag++)) 
  else 
   permitR=`egrep -v "^[[:space:]]*#" /etc/ssh/sshd_config|egrep -i 'Protocol.*'`
	if [ -n "$permitR" ];
	 then sed -i "s/$permitR/Protocol 2/g" /etc/ssh/sshd_config;
	 else echo "Protocol 2">>/etc/ssh/sshd_config;fi;
 fi 
 service sshd restart;
 if [ "$flag" -eq 2 ];then echo "OS_Linux_3 限制root用户远程登录-ssh合规"; else echo "OS_Linux_3 限制root用户远程登录-ssh不合规";fi;

sleep 3s
 #OS_Linux_4 控制用户缺省访问权限
mask=`cat /etc/login.defs|egrep -v "^[[:space:]]*#"|egrep -i umask|tail -n1`
if [ -n "$mask" ];
 then
permCode=`echo $mask|awk '{print $2}'`
if [ `echo "$permCode"|egrep '[0-7][2-7][7]'` ];
 then echo "OS_Linux_4 控制用户缺省访问权限合规";
 else echo "OS_Linux_4 控制用户缺省访问权限不合规";
  sed -i "s/$mask/UMASK 027/g" /etc/login.defs;
 fi;
 else echo "OS_Linux_4 控制用户缺省访问权限不合规";
  echo "UMASK 027">>/etc/login.defs;
fi;

sleep 3s
 #OS_Linux_5 控制FTP进程缺省访问权限

ftp_status=`ps -ef|egrep -v grep|egrep -i ftpd|wc -l` 
check_state() 
{ 
  if [ -f /etc/vsftpd.conf ]; 
   then 
  ftp_config="/etc/vsftpd.conf"; 
   else 
   if [ -f /etc/vsftpd/vsftpd.conf ]; 
   then 
  ftp_config="/etc/vsftpd/vsftpd.conf"; 
  fi; 
  fi; 
  if [ -f "$ftp_config" ]; 
  then 
   if ([ `egrep -v "^#" $ftp_config|egrep -i "chroot_list_enable=YES"|wc -l` -eq 1 ] && [ `egrep -v "^#" /etc/vsftpd/vsftpd.conf|grep -i "chroot_local_user=YES"|wc -l` -eq 0 ]); 
   then 
   if [ `egrep -v "^#" $ftp_config|egrep -i "chroot_list_file"|cut -d\= -f2` ]; 
  then 
  echo "OS_Linux_5 控制FTP进程缺省访问权限合规" 
  else 
    echo "OS_Linux_5 控制FTP进程缺省访问权限不合规"
	echo "chroot_list_file=/etc/vsftpd/chroot_list ">>$ftp_config
	if [ ! -f /etc/vsftpd/chroot_list ];then touch /etc/vsftpd/chroot_list;chmod 750 /etc/vsftpd/chroot_list;service vsftpd restart;fi;
  fi 
  else 
   echo "OS_Linux_5 控制FTP进程缺省访问权限不合规"
   echo "chroot_list_enable=YES ">>$ftp_config
   echo "chroot_local_user=NO ">>$ftp_config
   echo "chroot_list_file=/etc/vsftpd/chroot_list ">>$ftp_config
   if [ ! -f /etc/vsftpd/chroot_list ];then touch /etc/vsftpd/chroot_list;chmod 750 /etc/vsftpd/chroot_list;service vsftpd restart;fi; 
   fi 
  fi 
  unset ftp_config; 
  } 
if [ $ftp_status -eq 0 ]; 
  then 
  echo "OS_Linux_5 控制FTP进程缺省访问权限合规"; 
   else 
   check_state; 
  fi 

sleep 3s
 #OS_Linux_6 设备应配置日志功能，对用户登录进行记录
count=`last | wc -l`
if [ "$count" -eq 0 ];
 then echo "OS_Linux_6 设备应配置日志功能，对用户登录进行记录不合规";
 touch /var/log/wtmp;
 else echo "OS_Linux_6 设备应配置日志功能，对用户登录进行记录合规";
 fi;

sleep 3s
 #OS_Linux_7 启用syslog系统日志审计功能

flag=0
if [ -f /etc/syslog.conf ]; 
  then 
   authList=`cat /etc/syslog.conf | egrep  -v "^[[:space:]]*#" | egrep "authpriv" | egrep "/var/log/secure" --color=never;`
   if [ -n "$authList" ];
    then ((flag++));
	else echo "authpriv.* /var/log/secure">>/etc/syslog.conf;
	if [ ! -f /var/log/secure ];then touch /var/log/secure;chmod 640 /var/log/secure;/etc/init.d/syslog restart;fi;
	fi;
  fi; 
if [ -f /etc/rsyslog.conf ]; 
  then 
  authList=`cat /etc/rsyslog.conf | egrep -v "^[[:space:]]*#" | egrep "authpriv" | egrep "/var/log/secure" --color=never;`
   if [ -n "$authList" ];
    then ((flag++));
	else echo "authpriv.* /var/log/secure">>/etc/rsyslog.conf;
	if [ ! -f /var/log/secure ];then touch /var/log/secure;chmod 640 /var/log/secure;service rsyslog restart;fi;
	fi;
 fi
if [ -s /etc/syslog-ng/syslog-ng.conf ]; 
  then 
    fauthpriv=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "^[[:space:]]*filter" | egrep "facility[[:space:]]*\([[:space:]]*authpriv[[:space:]]*\)"| awk '{print $2}'`
    if [ -n "$fauthpriv" ];
    then 
      log_count=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "^[[:space:]]*log" | egrep $fauthpriv `
      if [ -n "$log_count" ];
      then ((flag++));
      else echo "filter f_authpriv { facility(authpriv); }; destination authpriv { file("/var/log/secure"); }; log { source(src); filter(f_authpriv); destination(authpriv); }; ">>/etc/syslog-ng/syslog-ng.conf;
	  if [ ! -f /var/log/secure ];then touch /var/log/secure;chmod 640 /var/log/secure;service rsyslog restart;fi;
      fi
    else
      echo "filter f_authpriv { facility(authpriv); }; destination authpriv { file("/var/log/secure"); }; log { source(src); filter(f_authpriv); destination(authpriv); }; ">>/etc/syslog-ng/syslog-ng.conf;
	  if [ ! -f /var/log/secure ];then touch /var/log/secure;chmod 640 /var/log/secure;service rsyslog restart;fi;
    fi
  fi
if [ "$flag" -ne 0 ];then echo "OS_Linux_7 启用syslog系统日志审计功能合规";else echo "OS_Linux_7 启用syslog系统日志审计功能不合规";fi;

sleep 3s
 #OS_Linux_8 系统日志文件由syslog创立并且不可被其他用户修改

flag=0
SYSLOGD_FLAG=`ps -ef |egrep ' syslogd '|egrep -v "grep"|wc -l`; 
SYSLOGNG_FLAG=`ps -ef |egrep "syslog-ng"|egrep -v "grep syslog-ng"|wc -l`; 
RSYSLOGD_FLAG=`ps -ef | egrep "rsyslogd" | egrep -v "grep" |wc -l`; 
if [ "$SYSLOGD_FLAG" != 0 ]; 
  then 
   LOGDIR=`if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf| egrep -v "^[[:space:]]*[#$]"|awk '{print $2}'|sed 's/^-//g'|egrep '^\s*\/' --color=never;fi`;
   MESSAGE_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-]-[x-][r-]-[x-]" | awk '{print $9}'`;
   if [ -n "$MESSAGE_NUM" ];
	then ((flag++))
	for var in $MESSAGE_NUM
     do
      chmod 640 $var
	 done;fi;
   OTHER_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-][w-][x-][r-]-[x-]" | awk '{print $9}'`;
   if [ -n "$OTHER_NUM" ];
	then ((flag++))
	for var in $OTHER_NUM
    do
     chmod 640 $var
	done;fi;
else 
   if [ "$RSYSLOGD_FLAG" != 0 ]; 
     then 
     LOGDIR=`cat /etc/rsyslog.conf | egrep -v "^[[:space:]]*[#$]"|awk '{print $2}'|sed 's/^-//g'|egrep '^\s*\/' --color=never`; 
     MESSAGE_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-]-[x-][r-]-[x-]" | awk '{print $9}'`;
     if [ -n "$MESSAGE_NUM" ];
	then ((flag++))
	for var in $MESSAGE_NUM
       do
        chmod 640 $var
	 done;fi;
      OTHER_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-][w-][x-][r-]-[x-]" | awk '{print $9}'`;
      if [ -n "$OTHER_NUM" ];
	      then ((flag++))
		  for var in $OTHER_NUM
          do
           chmod 640 $var
	      done; fi;
   else 
         if [ "$SYSLOGNG_FLAG" != 0 ]; 
            then 
            LOGDIR=`cat /etc/syslog-ng/syslog-ng.conf|egrep -v "^[[:space:]]*[#$]"|egrep "^destination"|egrep file|cut -d\" -f2`; 
           MESSAGE_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-]-[x-][r-]-[x-]" | awk '{print $9}'`;
          if [ -n "$MESSAGE_NUM" ];
	      then ((flag++))
		  for var in $MESSAGE_NUM
          do
           chmod 640 $var
	      done;fi;
         OTHER_NUM=`ls -l $LOGDIR 2>/dev/null|egrep -v "[r-][w-][x-][r-][w-][x-][r-]-[x-]" | awk '{print $9}'`;
         if [ -n "$OTHER_NUM" ];
	    then ((flag++))
          for var in $OTHER_NUM
          do
           chmod 640 $var;
	    done;fi;
	fi;
   fi; 
fi; 
if [ "$flag" -eq 0 ];then echo "OS_Linux_8 系统日志文件由syslog创立并且不可被其他用户修改合规"; else echo "OS_Linux_8 系统日志文件由syslog创立并且不可被其他用户修改不合规";fi;
unset SYSLOGD_FLAG SYSLOGNG_FLAG RSYSLOGD_FLAG LOGDIR;

sleep 3s
 #OS_Linux_9 启用记录cron行为日志功能

flag=0;
if [ -f /etc/syslog.conf ] 
  then 
   SYSLOG=`cat /etc/syslog.conf | egrep -v "^[[:space:]]*#" | egrep "cron.\*" --color=never|wc -l` 
   if [ "$SYSLOG" -ne 0 ];then ((flag++));else echo "cron.* /var/log/cron ">>/etc/syslog.conf;fi;
   if [ ! -f /var/log/cron ];then touch /var/log/cron;chmod 640 /var/log/cron;/etc/init.d/syslog restart;fi;
  fi 
if [ -f /etc/rsyslog.conf ] 
  then 
   RSYSLOG=`cat /etc/rsyslog.conf | egrep -v "^[[:space:]]*#" | egrep "cron.\*" --color=never|wc -l` 
   if [ "$RSYSLOG" -ne 0 ];then ((flag++));else echo "cron.* /var/log/cron ">>/etc/rsyslog.conf;fi;
   if [ ! -f /var/log/cron ];then touch /var/log/cron;chmod 640 /var/log/cron;service rsyslog restart ;fi;
  fi 
if [ -s /etc/syslog-ng/syslog-ng.conf ]; 
  then 
   cron_1=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "filter[[:space:]]*.*[[:space:]]*{[[:space:]]*facility\(cron\);[[:space:]]*};" | wc -l`; 
   if [ $cron_1 -ge 1 ]; 
  then 
  cron_2=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "destination[[:space:]]*.*[[:space:]]*{[[:space:]]*file\(\"/var/log/cron\"\)[[:space:]]*;[[:space:]]*};"|awk '{print $2}'`; 
  if [ -n $cron_2 ]; 
  then 
  cron_3=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "log[[:space:]]*{[[:space:]]*source\(src\);[[:space:]]*filter\(.*\);[[:space:]]*destination\($cron_2\);[[:space:]]*};" | wc -l`; 
   if [ $cron_3 -ge 1 ] 
  then 
   ((flag++))
  else 
   echo "filter f_cron { facility(cron); }; destination cron { file("/var/log/cron"); }; log { source(src); filter(f_cron); destination(cron); };">>/etc/syslog-ng/syslog-ng.conf;
   if [ ! -f /var/log/cron ];then touch /var/log/cron;chmod 640 /var/log/cron;/etc/init.d/syslog restart;fi;
  fi; 
  fi; 
  fi; 
fi;
if [ "$flag" -eq 0 ];then echo "OS_Linux_9 启用记录cron行为日志功能不合规";else echo "OS_Linux_9 启用记录cron行为日志功能合规";fi;

sleep 3s
 #OS_Linux_10 检查是否记录安全事件日志

flag=0
if [ -f /etc/syslog.conf ]; 
  then 
   syslog=`cat /etc/syslog.conf | egrep -v "^[[:space:]]*#" | egrep "*.err\;kern\.debug\;daemon\.notice[[:space:]]*/var/adm/messages"|wc -l`; 
   if [ $syslog -ge 1 ]; 
   then ((flag++))
   else 
    echo "*.err;kern.debug;daemon.notice /var/adm/messages">>/etc/syslog.conf
    if [ ! -f /var/adm/messages ];then touch /var/adm/messages;chmod 640 /var/adm/messages;/etc/init.d/syslog restart;fi;
   fi; 
  fi; 
if [ -f /etc/rsyslog.conf ]; 
  then 
   rsyslog=`cat /etc/rsyslog.conf | egrep -v "^[[:space:]]*#" | egrep "*.err\;kern\.debug\;daemon\.notice[[:space:]]*/var/adm/messages"|wc -l`; 
  if [ $rsyslog -ge 1 ]; 
   then ((flag++))
  else 
  echo "*.err;kern.debug;daemon.notice /var/adm/messages">>/etc/rsyslog.conf
  if [ ! -f /var/adm/messages ];then touch /var/adm/messages;chmod 640 /var/adm/messages;service rsyslog  restart;fi;  
  fi; 
  fi; 
if [ -f /etc/syslog-ng/syslog-ng.conf ]; 
  then suse_ret=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "level(err) or facility(kern) and level(debug) or facility(daemon) and level(notice)" --color=never`; 
   if [ -n "$suse_ret" ]; 
   then suse_ret2=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep 'file("/var/adm/msgs")' --color=never`; 
  if [ -n "$suse_ret2" ]; 
  then suse_ret3=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "destination(msgs)" --color=never`; 
  fi; 
  fi; 
 if [ -n "$suse_ret3" ]; 
  then ((flag++)) 
  else  
  echo "filter f_msgs { level(err) or facility(kern) and level(debug) or facility(daemon) and level(notice); }; destination msgs { file(""/var/adm/msgs""); }; log { source(src); filter(f_msgs); destination(msgs); };">>/etc/syslog-ng/syslog-ng.conf
  if [ ! -f /var/adm/messages ];then touch /var/adm/messages;chmod 640 /var/adm/messages;/etc/init.d/syslog restart;fi;  
  fi;
fi;
if [ "$flag" -eq 0 ];then echo "OS_Linux_10 检查是否记录安全事件日志不合规";else echo "OS_Linux_10 检查是否记录安全事件日志合规"; fi;

sleep 3s
 #OS_Linux_11 需要重点关注的日志内容传输到日志服务器
flag=0
if [ -s /etc/syslog-ng/syslog-ng.conf ]; 
  then 
   ret_1=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | grep "port(514)"|awk -F '{' '{print $1}'|awk '{print $2}'`; 
   if [ -n "$ret_1" ]; 
   then 
  ret_2=`cat /etc/syslog-ng/syslog-ng.conf | egrep -v "^[[:space:]]*#" | egrep "destination\($ret_1\)" --color=never`; 
   if [ ! -n "$ret_2" ]; 
   then  flag=1;
  echo "destination logserver { udp(""192.168.123.123"" port(514)); };">>/etc/syslog-ng/syslog-ng.conf;
  echo "log { source(src); destination(logserver); };">>/etc/syslog-ng/syslog-ng.conf;
  /etc/init.d/syslog restart;
  fi;
  else flag=1;
  echo "destination logserver { udp(""192.168.123.123"" port(514)); };">>/etc/syslog-ng/syslog-ng.conf;
  echo "log { source(src); destination(logserver); };">>/etc/syslog-ng/syslog-ng.conf;
  /etc/init.d/syslog restart;
  fi;   
  fi; 
if [ -s /etc/rsyslog.conf ]; 
  then serverip=`cat /etc/rsyslog.conf | egrep -v "^[[:space:]]*#" | egrep -E '[[:space:]]*.+@.+' --color=never| wc -l`
  if [ "$serverip" -eq 0 ];then echo "*.*@192.168.0.1">>/etc/rsyslog.conf;service rsyslog restart ; flag=1; fi;
  else 
  if [ -f /etc/syslog.conf ]; 
  then 
   serverip=`cat /etc/syslog.conf | egrep -v "^[[:space:]]*#" | egrep -E '[[:space:]]*.+@.+' --color=never|wc -l`
   if [ "$serverip" -eq 0 ];then echo "*.*@192.168.0.1">>/etc/syslog.conf;/etc/init.d/syslog restart;flag=1;fi;
  fi; 
fi
if [ "$flag" -ne 0 ];then echo "OS_Linux_11 需要重点关注的日志内容传输到日志服务器不合规";
 else echo "OS_Linux_11 需要重点关注的日志内容传输到日志服务器合规"; 
 fi;
 



sleep 3s
 #OS_Linux_12 设备是否配置使用SSH等加密协议
flag=0
telnetStatus=$((`systemctl status telnet.socket |grep "listening"|wc -l`+`service telnet status|grep "listening"|wc -l`)) 
sshStatus=`service sshd status |grep "running"|wc -l` 
if [ "$telnetStatus" -ne 0 ];then ((flag++));service telnet stop;systemctl stop telnet.socket ;fi;
if [ "$sshStatus" -eq 0 ];then ((flag++));service sshd start;fi;
if [ "$flag" -eq 0 ];then echo "OS_Linux_12 设备是否配置使用SSH等加密协议合规";else echo "OS_Linux_12 设备是否配置使用SSH等加密协议不合规";fi;

sleep 3s
#OS_Linux_13 应删除或锁定与设备运行、维护等工作无关的账号
shadowList=`egrep "^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:|^adm:|^shutdown:" /etc/shadow|awk -F: '($2!~/\*(.*)/) {print $1":"$2}'`
pwdList=`egrep "^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:|^adm:|^shutdown:" /etc/passwd|awk -F: '($7!~/bin\/false/) {print $1":"$7}'` 
num_of_LK=`echo $shadowList|grep "^$"|wc -l`
num_of_shell=`echo $pwdList|grep "^$"|wc -l`
((num_of_LK--))
((num_of_shell--))
if [ `expr "$num_of_LK" + "$num_of_shell"` -eq 0 ];
 then echo "OS_Linux_13 应删除或锁定与设备运行、维护等工作无关的账号合规";
 else echo "OS_Linux_13 应删除或锁定与设备运行、维护等工作无关的账号不合规"；
  pwdList=`egrep "^lp:|^sync:|^halt:|^news:|^uucp:|^operator:|^games:|^gopher:|^smmsp:|^nfsnobody:|^nobody:|^adm:|^shutdown:" /etc/passwd`
  for var1 in $shadowList
  do
   str1=`echo $var1|cut -d: -f1`;
	#Update 2021.6.8 修复替换语句
    sed -i "s#$var1#$str1\:\*#g" /etc/shadow;
  done
  for var2 in $pwdList
  do
   str2=`echo $var2|awk -F':' '{print $NF}'|egrep '\/'s`
	if [ -n "$str2" ];then sed -i "s#$str2#/bin/false#g" /etc/passwd;fi;
  done
fi


sleep 3s
 #OS_Linux_14 修改系统banner

ssh_status=`ps -ef|egrep "sshd"|egrep -v "grep"|wc -l`; 
flag=0;
if [ -s /etc/issue ] 
 then 
  redhat_count=`cat /etc/issue | egrep -i "Red Hat" | wc -l` 
  suse_count=`cat /etc/issue | egrep -i "suse" | wc -l`
  centos_count=`cat /etc/issue | egrep -i "CentOS" | wc -l`
  else 
  redhat_count=0
  suse_count=0
  centos_count=0
 fi 
if ([ $redhat_count -ge 1 ] || [ $suse_count -ge 1 ] || [ $centos_count -ge 1 ]) 
 then beforeresult=1; 
 else 
 beforeresult=0;
 fi;
if [ -s /etc/issue.net ] 
 then 
  redhat_count=`cat /etc/issue.net | egrep -i "Red Hat" | wc -l` 
  suse_count=`cat /etc/issue.net | egrep -i "suse" | wc -l`
  centos_count=`cat /etc/issue | egrep -i "CentOS" | wc -l`
  else
  redhat_count=0
  suse_count=0
  centos_count=0
 fi 
if ([ $redhat_count -ge 1 ] || [ $suse_count -ge 1 ] || [ $centos_count -ge 1 ]) 
 then telnetresult=1 
 else telnetresult=0
 fi
if [ $ssh_status -ne 0 ]
 then 
 if [ -f /etc/ssh/sshd_config ] 
  then 
  ssh_bannerfile=`cat /etc/ssh/sshd_config |sed '/^\s*#/d'| egrep "Banner" | awk '{print $2}'`
  if ( [ -s /etc/motd ] && [ $ssh_bannerfile ]); 
   then 
    ((flag++));
   else
	if [ ! $ssh_bannerfile ];
	 then echo "Banner /etc/ssh/ssh_banner">>/etc/ssh/sshd_config
	 echo "Warning!!! If you are not the operations staff, loggout the system right now">>/etc/ssh/ssh_banner 
	 fi;
	#update2021.6.8
	if [ ! -s /etc/motd ];then echo " Authorized users only. All activity may be monitored and reported ">> /etc/motd;fi;
   fi;
  else 
   echo "Banner /etc/ssh/ssh_banner ">>/etc/ssh/sshd_config
   echo "Warning!!! If you are not the operations staff, loggout the system right now">/etc/ssh/ssh_banner 
  fi;
 else 
  ((flag++));
fi; 
telnet_status=`netstat -an|egrep ":23\>"|egrep -i listen|wc -l`;
if ([ $telnetresult -eq 1 ] && [ $telnet_status -eq 1 ]); 
 then 
  echo " Authorized users only. All activity may be monitored and reported " > /etc/issue 
  echo " Authorized users only. All activity may be monitored and reported " > /etc/issue.net
  else 
  if [ $telnetresult -eq 1 ]; 
 then 
  ((flag++))
 else 
  if [ $telnet_status -eq 1 ]; 
 then 
  ((flag++))
 else 
  ((flag++))
 fi; 
 fi; 
 fi;
if [ "$flag" -eq 2 ];then echo "OS_Linux_14 修改系统banner合规";else echo "OS_Linux_14 修改系统banner不合规";fi


sleep 3s
 #OS_Linux_15 配置定时帐户自动登出
check_tmp_var=`cat /etc/profile |egrep -v "^[[:space:]]*#"|egrep -v "^$"|egrep -i "TMOUT=[0-9]+" | cut -d= -f 2`;
check_result_flag=0;
if [ -n "$check_tmp_var" ];
 then   if [ "$check_tmp_var" -le 180 ];
  then   check_result_flag=1 ;
  else  sed -i "s/TMOUT=.*/TMOUT=180/g" /etc/profile;
     source /etc/profile;
  fi;
 else  echo "TMOUT=180">>/etc/profile;
   echo "export TMOUT">>/etc/profile;
   source /etc/profile;
fi;
if [ "$check_result_flag" -eq 1 ];
 then echo "OS_Linux_15 配置定时帐户自动登出合规"
 else echo "OS_Linux_15 配置定时帐户自动登出不合规"
fi;

sleep 3s
 #OS_Linux_16 删除潜在危险文件
netrc_num=`find / -maxdepth 3 -name .netrc 2>/dev/null|wc -l` 
rhosts_num=`find / -maxdepth 3 -name .rhosts 2>/dev/null|wc -l` 
equiv_num=`find / -maxdepth 3 -name hosts.equiv 2>/dev/null|wc -l`
if [[ `expr $netrc_num+$rhosts_num+$equiv_num` -eq 0 ]];
 then echo "OS_Linux_16 删除潜在危险文件合规";
 else echo "OS_Linux_16 删除潜在危险文件不合规";
  for var in `find / -maxdepth 3 -name .netrc 2>/dev/null` 
  do
   rm -f $var
  done
  for var in `find / -maxdepth 3 -name .rhosts 2>/dev/null` 
  do
   rm -f $var
  done
  for var in `find / -maxdepth 3 -name hosts.equiv 2>/dev/null` 
  do
   rm -f $var
  done
 fi;

#OS_Linux_17 禁止root登陆FTP
 
FTP_STATUS=`ps -ef|egrep ftpd|egrep -v "grep "|wc -l`; 
ftp_check_enchance ()
{	
  if [ -n "$FTPUSERS_PAM" ];
   then echo "root">>$FTPUSERS_PAM;
   else sed -i "root" $FTP_USER;
  fi;
  service vsftpd restart;
  return 0;
} 
ftp_check_func2 () 
  { 
  if [ -f /etc/vsftpd.conf ]; 
   then 
  FTP_CONF="/etc/vsftpd.conf"; 
   FTP_USER=`cat $FTP_CONF|egrep -v "^#"|egrep userlist_file|cut -d= -f2`; 
   vsftpconf_check; 
   else 
   if [ -f /etc/vsftpd/vsftpd.conf ]; 
   then 
  FTP_CONF="/etc/vsftpd/vsftpd.conf"; 
   FTP_USER=`cat $FTP_CONF|egrep -v "^#"|egrep userlist_file|cut -d= -f2`; 
   vsftpconf_check; 
  fi; 
  fi; 
  } 
vsftpconf_check () 
  { 
  userlist_enable=`egrep -v "^#" $FTP_CONF|egrep -i "userlist_enable=YES"|wc -l`; 
  userlist_deny=`egrep -v "^#" $FTP_CONF|egrep -i "userlist_deny=NO"|wc -l`; 
  if  [ $userlist_enable = 1 -a $userlist_deny = 1 ]; 
  then 
   if [ -n "$FTP_USER" ] 
   then 
  if [ `egrep -v "^#" $FTP_USER|egrep "^root$"|wc -l` = 0 ]; 
   then 
  echo "OS_Linux_17 禁止root登陆FTP合规"; 
   else 
  echo "OS_Linux_17 禁止root登陆FTP不合规";
  ftp_check_enchance  
   fi; 
   else 
  echo "OS_Linux_17 禁止root登陆FTP不合规"; 
  ftp_check_enchance
   fi; 
  else 
   echo "OS_Linux_17 禁止root登陆FTP不合规"; 
   ftp_check_enchance
  fi; 
  }
ftp_check_func1 () 
  { 
  if [ -f  /etc/pam.d/vsftpd ]; 
   then 
   FTPUSERS_PAM=`egrep "file" /etc/pam.d/vsftpd|egrep -v "^#"|sed 's/^.*file=//g'|awk '{print $1}'` 
  if [ -n "$FTPUSERS_PAM" ] 
  then 
  if [ `egrep -v "^#" $FTPUSERS_PAM|egrep "^root$"|wc -l` = 1 ]; 
   then 
  echo "OS_Linux_17 禁止root登陆FTP合规"; 
   else 
  ftp_check_func2; 
   fi 
  else 
  ftp_check_func2; 
  fi 
   else 
   echo "/etc/pam.d/vsftpd not exist"; 
  ftp_check_func2; 
  fi;
  } 
if [ $FTP_STATUS -eq 0 ]; 
  then  echo "OS_Linux_17 禁止root登陆FTP合规"; 
   else  ftp_check_func1; 
  fi 
unset FTP_STATUS FTP_CONF FTP_USER FTPUSERS_PAM

sleep 3s
 #OS_Linux_18 禁止匿名FTP

if [ `ps -ef|egrep ftpd|egrep -v "grep"|wc -l` -ge 1 ]; 
  then 
   if [ -f /etc/vsftpd.conf ]; 
   then 
   cat /etc/vsftpd.conf|egrep -v "^[[:space:]]*#"|egrep -v "^[[:space:]]*$"|egrep -i "anonymous_enable" --color=never;
	if [ `echo "$str"|grep -i "YES"` ];
	then echo "OS_Linux_18 禁止匿名FTP不合规";
	sed -i "s/$str/anonymous_enable=NO/g" /etc/vsftpd/vsftpd.conf;
	service vsftpd restart;
	else echo "OS_Linux_18 禁止匿名FTP合规";
	fi;
   else 
  if [ -f /etc/vsftpd/vsftpd.conf ]; 
   then 
   str=`cat /etc/vsftpd/vsftpd.conf|egrep -v "^[[:space:]]*#"|egrep -v "^[[:space:]]*$"|egrep -i "anonymous_enable" --color=never; `
   if [ `echo "$str"|grep -i "YES"` ];
	then echo "OS_Linux_18 禁止匿名FTP不合规";
	sed -i "s/$str/anonymous_enable=NO/g" /etc/vsftpd/vsftpd.conf;
	service vsftpd restart;
	else echo "OS_Linux_18 禁止匿名FTP合规";
	fi;
   fi;
   fi; 
   else 
   echo "OS_Linux_18 禁止匿名FTP合规"; 
  fi; 

sleep 3s
 #OS_Linux_19 修改FTP Banner信息
 
FTP_STATUS=`ps -ef|egrep ftpd|egrep -v grep|wc -l` 
ftp_check_func () 
  { 
  if [ -f /etc/vsftpd.conf ]; 
  then 
  FTPCONF="/etc/vsftpd.conf"; 
  else 
   if [ -f /etc/vsftpd/vsftpd.conf ]; 
   then 
  FTPCONF="/etc/vsftpd/vsftpd.conf"; 
   fi; 
  fi; 
  if [ -f "$FTPCONF" ] 
  then 
   if [ `egrep -v "^[[:space:]]*#" $FTPCONF|egrep -i "banner_file"|wc -l` -ne 0 ]; 
   then 
   banner_file = `egrep -v "^[[:space:]]*#" $FTPCONF|egrep -i "banner_file"|awk -F"=( )*" '{print $2}'`
   if [ -f $banner_file ] 
    then 
    echo "OS_Linux_19 修改FTP Banner信息合规";
   else 
    echo "OS_Linux_19 修改FTP Banner信息不合规";
	str=`egrep -v "^[[:space:]]*#" $FTPCONF|egrep -i "ftpd_banner"`
	if [ -n "$str" ]; then sed -i "s/$str/ftpd_banner=Welcome to FTP./g" $banner_file;fi;
   fi;
   else if [ `egrep -v "^[[:space:]]*#" $FTPCONF|egrep -i "ftpd_banner"|wc -l` -ne 0 ];
   then
    echo "OS_Linux_19 修改FTP Banner信息合规"; 
   else 
    echo "OS_Linux_19 修改FTP Banner信息不合规"; 
	str=`egrep -v "^[[:space:]]*#" $FTPCONF|egrep -i "ftpd_banner"`
	if [ -n "$str" ]; then sed -i "s/$str/ftpd_banner=Welcome to FTP./g" $FTPCONF;
else echo "ftpd_banner=Welcome to FTP.">>$FTPCONF;fi;
   fi; 
  fi; 
  fi;
  unset FTPCONF; 
  } 
if [ $FTP_STATUS -eq 0 ]; 
  then 
   echo "OS_Linux_19 修改FTP Banner信息合规" 
  else 
   ftp_check_func; 
 fi;

sleep 3s
 #OS_Linux_20 检查SNMP配置-修改SNMP的默认Community

snmp_status=`ps -ef|egrep snmpd|egrep -v "grep"|wc -l`; 
snmp_check_fun() 
  { 
  if [ -f /etc/snmp/snmpd.conf ]; 
  then snmp_config=/etc/snmp/snmpd.conf; 
  else snmp_config=/etc/snmpd.conf; 
  fi; 
  egrep -v "^#" $snmp_config|egrep "community"; 
  if [ `egrep -v "^#" $snmp_config|egrep "rocommunity|rwcommunity"|egrep "public|private"|wc -l` -eq 0 ]; 
  then echo "OS_Linux_20 检查SNMP配置-修改SNMP的默认Community合规"; 
  else echo "OS_Linux_20 检查SNMP配置-修改SNMP的默认Community不合规"; 
	str=`cat $snmp_config|egrep -i '^r[ow]community.*'|awk '{print $2}'`;
	if [ -n "$str" ];then cat $snmp_config|egrep -i '^r[ow]community.*'|sed -i "s/$str/new_community_name/g" $snmp_config;
	service snmpd restart;fi;
  fi; 
  } 
if [ "$snmp_status" -ge  1 ]; 
  then snmp_check_fun; 
  else echo "OS_Linux_20 检查SNMP配置-修改SNMP的默认Community合规"; 
  fi 
unset snmp_status snmp_config;

sleep 3s
 #OS_Linux_21 用户最小权限
flag=0;
passwd_count=`ls -lL /etc/passwd 2>/dev/null|grep -v "[r-][w-]-[r-]--[r-]--"|wc -l` 
if [ $passwd_count -ne 0 ]; then  chmod 644 /etc/passwd ;else ((flag++)); fi;
group_count=`ls -lL /etc/group 2>/dev/null|grep -v "[r-][w-]-[r-]--[r-]--"|wc -l` 
if [ $group_count -ne 0 ]; then  chmod 644 /etc/group ;else ((flag++)); fi;
services_count=`ls -lL /etc/services 2>/dev/null|grep -v "[r-][w-]-[r-]--[r-]--"|wc -l` 
if [ $services_count -ne 0 ]; then  chmod 644 /etc/services ;else ((flag++)); fi;
shadow_count=`ls -lL /etc/shadow 2>/dev/null|grep -v "[r-]--------"|wc -l` 
if [ $shadow_count -ne 0 ]; then  chmod 400 /etc/shadow ;else ((flag++)); fi;
xinetd_count=`ls -lL /etc/xinetd.conf 2>/dev/null|egrep -v "[r-][w-]-------"|wc -l` 
if [ $xinetd_count -ne 0 ]; then  chmod 600 /etc/xinetd.conf ;else ((flag++)); fi;
security_count=`ls -lLd /etc/security 2>/dev/null|egrep -v "[r-][w-]-------"|wc -l`
if [ $security_count -ne 0 ]; then  chmod 600 /etc/security ;else ((flag++)); fi;
if [ $flag -eq 6 ]; then echo "OS_Linux_21 用户最小权限合规"; else echo "OS_Linux_21 已重新设置用户最小权限";fi;

sleep 3s
#OS_Linux_22 禁止IP源路由
flag=1
check_tmp_var_sring=`cat /proc/sys/net/ipv4/conf/*/accept_source_route | sed ":a;N;s/\n/,/g;ta"`;
 check_tmp_var_arr=($(echo $check_tmp_var_sring | tr ',' ' ')); 
 for i in "${check_tmp_var_arr[@]}"; 
 do    
 if [ "$i" -ne 0 ]; 
 then echo "OS_Linux_22 禁止IP源路由不合规"; 
 flag=0;
 break;  
 fi; 
 done;
if [ "$flag" -eq 1 ];
then echo "OS_Linux_22 禁止IP源路由合规";
else for ipsroute in /proc/sys/net/ipv4/conf/*/accept_source_route ;
do echo 0 > $ipsroute 
done;
fi;
sleep 3s

#OS_Linux_23 查看所有用户、用户组
echo "OS_Linux_23 查看所有用户、用户组";
gid_min=`(egrep -v ^# /etc/login.defs |egrep "^GID_MIN"|awk '($1="GID_MIN") {print $2}')` 
gid_max=`(egrep -v ^# /etc/login.defs |egrep "^GID_MAX"|awk '($1="GID_MAX") {print $2}')` 
egrep -v "oracle|sybase|postgres|informix" /etc/passwd|awk -F: '($4>='$gid_min' && $4<='$gid_max') {print $1":"$3":"$4}' 
echo $gid_min $gid_max 
echo "result="`egrep -v "oracle|sybase|postgres|informix" /etc/passwd|awk -F: '($4>='$gid_min' && $4<='$gid_max') {print $1":"$3":"$4}'|wc -l` 
unset gid_min gid_max

sleep 3s
 #OS_Linux_24 主机访问控制_IP限制合规（重启服务）
cat /etc/hosts.allow |sed '/^#/d'|sed '/^$/d'|egrep -i "all|sshd|telnet" --color=never
cat /etc/hosts.deny |sed '/^#/d'|sed '/^$/d'|egrep -i ":all"|egrep -i "all|sshd|telnet" --color=never
flag=0;
allowno=`egrep -i "sshd|telnet|all" /etc/hosts.allow |sed '/^#/d'|sed '/^$/d'|wc -l` 
if [ "$allowno" -eq 0 ]; then echo "all:all">>/etc/hosts.allow;else ((flag++));fi;
denyno=`egrep -i "sshd|telnet|all" /etc/hosts.deny |egrep -i ":all" |sed '/^#/d'|sed '/^$/d'|wc -l`
if [ "$denyno" -eq 0 ]; then echo "all:all">>/etc/hosts.deny;else ((flag++));fi;
if [ "$flag" -eq 2 ];then echo "OS_Linux_24 主机访问控制_IP限制合规";
 else echo "OS_Linux_24 主机访问控制_IP限制不合规";
  /etc/rc.d/init.d/xinetd restart;
  /etc/rc.d/init.d/network restart;
 fi;

sleep 3s
 #OS_Linux_25	检查是否禁止ip路由转发（重启服务）
ip_f=`/sbin/sysctl -n net.ipv4.ip_forward` 
if [ "$ip_f" -eq 0 ]; then echo "OS_Linux_25 禁止ip路由转发合规";
 else echo "OS_Linux_25 禁止ip路由转发不合规";
 if [ ! `cat /etc/sysctl.conf| egrep "net.ipv4.ip_forward"|wc -l` ];
  then echo "net.ipv4.ip_forward = 0">>/etc/sysctl.conf;
  else sed -i "s/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/g" /etc/sysctl.conf;
 fi;
 /sbin/sysctl -p;
fi;
		
sleep 3s
 #OS_Linux_26	禁止icmp重定向合规（重启服务）
arNum=`/sbin/sysctl -n net.ipv4.conf.all.accept_redirects` 
if [ $arNum -eq 0 ]; then echo "OS_Linux_26 禁止icmp重定向合规";
 else echo "OS_Linux_26 禁止icmp重定向不合规";
 conft=`cat /etc/sysctl.conf|grep "net.ipv4.conf.all.accept_redirects"`
 if [ -z "$conft" ] ;
  then echo "net.ipv4.conf.all.accept_redirects = 0">>/etc/sysctl.conf;
  else sed -i "s/net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/g" /etc/sysctl.conf;
 fi;
 /sbin/sysctl -p;
fi;

sleep 3s
 #OS_Linux_27 检查是否配置ntp
ntpstatus=`ps -ef|egrep "ntp|ntpd"|egrep -v grep|wc -l` 
if [ $ntpstatus != 0 ]; 
  then 
  ntpservernum=`cat /etc/ntp.conf|egrep "^server"|egrep -v "127.127.1.0"|egrep -v "127.0.0.1"|wc -l`; 
  if [ $ntpservernum -eq 0 ];then echo "OS_Linux_27 检查配置ntp不合规";echo "server 10.0.0.1">>/etc/ntp.conf; /etc/init.d/ntpd restart;service ntpd restart ;else echo "OS_Linux_27 检查配置ntp合规";fi;
   else 
	echo "OS_Linux_27 检查配置ntp不合规";
	/etc/init.d/ntpd restart;service ntpd restart ;
  fi 
unset ntpstatus ntpservernum;

sleep 3s
 #OS_Linux_28 查看是否使用PAM禁止任何人su为root
str=`cat /etc/pam.d/su|egrep -v "^[[:space:]]*#"|egrep -v "^$"|egrep "^auth"`
flag=0;
str1=`echo "$str"|egrep 'auth\s*sufficient\s*pam_rootok.so'`
str2=`echo "$str"|egrep 'auth\s*required\s*pam_wheel.so\s*use_uid'`
if [ -z "$str1" ]; then echo "auth  sufficient  pam_rootok.so">>/etc/pam.d/su ;else ((flag++));fi;
if [ -z "$str2" ]; then echo "auth  required  pam_wheel.so  use_uid ">>/etc/pam.d/su ;else((flag++));fi;
if [ $flag -eq 2 ]; then echo "OS_Linux_28 PAM禁止任何人su成为root合规";else echo "OS_Linux_28 PAM禁止任何人su成为root不合规";fi;

sleep 3s
 #OS_Linux_29 静态口令是否符合标准

Calculate () 
  { 
   DCREDIT=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw "dcredit"|sed 's/^.*dcredit[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`; 
   LCREDIT=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw "lcredit"|sed 's/^.*lcredit[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`; 
   UCREDIT=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw "ucredit"|sed 's/^.*ucredit[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`; 
   OCREDIT=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw "ocredit"|sed 's/^.*ocredit[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`; 
   MINLEN=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw  "minlen"|sed 's/^.*minlen[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`;
   if [ -z $DCREDIT ]; then DCREDIT=0; else if [ $DCREDIT -lt 0 ]; then DCREDIT=1; fi; fi;
   if [ -z $LCREDIT ]; then LCREDIT=0; else if [ $LCREDIT -lt 0 ]; then LCREDIT=1; fi; fi;
   if [ -z $UCREDIT ]; then UCREDIT=0; else if [ $UCREDIT -lt 0 ]; then UCREDIT=1; fi; fi;
   if [ -z $OCREDIT ]; then OCREDIT=0; else if [ $OCREDIT -lt 0 ]; then OCREDIT=1; fi; fi;
   
   MINCLASS=`expr $DCREDIT + $LCREDIT + $UCREDIT + $OCREDIT`;
   if [ $MINCLASS -eq 4 ]; then echo "OS_Linux_29 静态口令标准合规";
	else echo "OS_Linux_29 静态口令标准不合规";
	if [ $flag -eq 0 ];
		then sed -i 's/password    requisite.*/password     requisite     pam_cracklib.so retry=3 minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/g' $FILE_NAME;fi;
	if [ $flag -eq 2 ];
		then echo "password     required     pam_pwcheck.so nullok password requisite pam_cracklib.so minlen=8 dcredit=-1 lcredit=-1 ucredit=-1 ocredit=-1 use_authtok password required pam_unix2.so nullok use_first_pass use_authtok">>$FILE_NAME;fi;
	if [ $flag -eq 1 ];
		then sed -i 's/password    requisite.*/password    requisite     pam_pwquality.so retry=3 minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/g' $FILE_NAME;fi;
	fi;
   unset DCREDIT LCREDIT UCREDIT OCREDIT MINLEN MINCLASS; 
  } 
flag=0
if ([ -d /etc/pam.d ] && [ -f /etc/pam.d/common-password ] );
  then
    FILE_NAME=/etc/pam.d/common-password;
    Calculate;
  fi

if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]); 
  then 
   FILE_NAME=/etc/pam.d/system-auth; 
   seven=`cat $FILE_NAME|egrep -v "^#|^$"|egrep -iw  "pam_pwquality.so"|sed 's/^.*pam_pwquality.so[[:space:]]*=[[:space:]]*//g'|sed 's/\s.*$//g'`
   if [ -n $seven ];then flag=1 ;fi;
   Calculate; 
  fi 

suse_version=`cat /etc/SuSE-release 2>/dev/null|grep -i "VERSION"|awk '{print $3}'` 
if ([ "x$suse_version" = x10 ] || [ "x$suse_version" = x11 ]) 
  then 
   flag=2;
   FILE_NAME=/etc/pam.d/common-password 
   Calculate; 
   else 
  if [ -f /etc/SuSE-release ] 
  then 
   FILE_NAME=/etc/pam.d/passwd 
   Calculate; 
  fi 
  fi

sleep 3s
 #OS_Linux_30 检查静态口令最长生存期
flag=0;
max=`cat /etc/login.defs |egrep -v "^[[:space:]]*#"|egrep -E '^\s*PASS_MAX_DAYS' --color=never|awk '{print $2}'`
if [ $max -le 90 ];then ((flag++));
	else sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs;fi;
min=`cat /etc/login.defs |egrep -v "^[[:space:]]*#"|egrep -E '^\s*PASS_MIN_DAYS' --color=never|awk '{print $2}'`
if [ $min -ge 6 ];then ((flag++));
	else sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/g' /etc/login.defs;fi;
len=`cat /etc/login.defs |egrep -v "^[[:space:]]*#"|egrep -E '^\s*PASS_MIN_LEN' --color=never|awk '{print $2}'`
# ADD1 PASS_MIN_LEN_CHECK 2021.6.3
if [ $len -ge 8 ];then ((flag++));
	else sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN 8/g' /etc/login.defs;fi;
warn=`cat /etc/login.defs |egrep -v "^[[:space:]]*#"|egrep -E '^\s*PASS_WARN_AGE' --color=never|awk '{print $2}'`
if [ $warn -ge 7 ];then ((flag++));
	else sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/g' /etc/login.defs;fi;
if [ $flag -eq 4 ];then echo "OS_Linux_30 静态口令生存期合规";else echo "静态口令生存期不合规";fi;

sleep 3s
 #OS_Linux_31 检查口令锁定策略

if ([ -d /etc/pam.d ] && [ -f /etc/pam.d/common-password ] );
  then FILE_NAME=/etc/pam.d/common-password;
    str=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep -i "auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so" --color=never `
	if [ -n "$str" ] ;
	then echo "OS_Linux_31 口令锁定策略合规";
	else echo "OS_Linux_31 口令锁定策略不合规"
	echo "auth required pam_tally2.so deny=5 onerr=fail no_magic_root unlock_time=180">>/etc/pam.d/common-password
	echo "account  required  pam_tally2.so">>/etc/pam.d/common-password;
	fi
  fi
if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]); 
  then FILE_NAME=/etc/pam.d/system-auth 
   str=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep -i "auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so" --color=never`
   if [ -n "$str" ] ;
	then echo "OS_Linux_31 口令锁定策略合规";
	else echo "OS_Linux_31 口令锁定策略不合规"
	echo "auth required pam_tally2.so deny=5 onerr=fail no_magic_root unlock_time=180">>/etc/pam.d/system-auth
	echo "account  required  pam_tally2.so">>/etc/pam.d/system-auth;
	fi
  fi 
suse_version=`cat /etc/SuSE-release 2>/dev/null|grep -i "VERSION"|awk '{print $3}'` 
if ([ "x$suse_version" = x10 ] || [ "x$suse_version" = x11 ]) 
  then 
   FILE_NAME=/etc/pam.d/common-password 
   str=`cat $FILE_NAME|grep -v '^#'|egrep -i "auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so" --color=never`
   if [ -n "$str" ] ;
	then echo "OS_Linux_31 口令锁定策略合规";
	else echo "OS_Linux_31 口令锁定策略不合规"
	echo "auth required pam_tally2.so deny=5 onerr=fail no_magic_root unlock_time=180">>/etc/pam.d/common-password 
	echo "account  required  pam_tally2.so">>/etc/pam.d/common-password ;
	fi
   else 
  if [ -f /etc/SuSE-release ] 
  then 
  FILE_NAME=/etc/pam.d/passwd 
  str=`cat $FILE_NAME|grep -v '^#'|egrep -i "auth[[:space:]]*required[[:space:]]*pam_tally.so|auth[[:space:]]*required[[:space:]]*pam_tally2.so|account[[:space:]]*required[[:space:]]*pam_tally.so|account[[:space:]]*required[[:space:]]*pam_tally2.so" --color=never`
  if [ -n "$str" ] ;
	then echo "OS_Linux_31 口令锁定策略合规";
	else echo "OS_Linux_31 口令锁定策略不合规"
	echo "auth required pam_tally2.so deny=5 onerr=fail no_magic_root unlock_time=180">>/etc/pam.d/passwd 
	echo "account  required  pam_tally2.so">>/etc/pam.d/passwd ;
	fi
  fi 
  fi 
unset suse_version FILE_NAME;

sleep 3s
 #OS_Linux_32 检查口令重复次数

if ([ -d /etc/pam.d ] && [ -f /etc/pam.d/common-password ] );
  then FILE_NAME=/etc/pam.d/common-password;
	str1=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep password --color=never |egrep sufficient`
	str2=`echo "$str1"|egrep "(.*)password(\s)+sufficient(\s)+pam_unix.so(.*)remember=([5-9]|([1-9][0-9]+))(.*)"`
	if [ -n "$str1" ];
		then if [ -n "$str2" ];
				then echo "OS_Linux_32 口令重复次数合规";
				else cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
				sed -i 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/common-password;
				echo "OS_Linux_32 口令重复次数不合规"
				fi;
		else 
		cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
		echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5">> /etc/pam.d/common-password;
		echo "OS_Linux_32 口令重复次数不合规"
	fi
  fi
if ([ -f /etc/redhat-release ] && [ -f /etc/pam.d/system-auth ]); 
  then FILE_NAME=/etc/pam.d/system-auth 
	str1=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep password --color=never|egrep sufficient`
	str2=`echo "$str1"|egrep "(.*)password(\s)+sufficient(\s)+pam_unix.so(.*)remember=([5-9]|([1-9][0-9]+))(.*)"`
	if [ -n "$str1" ];
		then if [ -n "$str2" ];
				then echo "OS_Linux_32 口令重复次数合规";
				else cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
				sed -i 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/system-auth;
				echo "OS_Linux_32 口令重复次数不合规"
				fi
		else 
		cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
		echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5">> /etc/pam.d/system-auth;
		echo "OS_Linux_32 口令重复次数不合规"
	fi;
fi 
suse_version=`cat /etc/SuSE-release 2>/dev/null|egrep -i "VERSION"|awk '{print $3}'` 
if ([ "x$suse_version" = x10 ] || [ "x$suse_version" = x11 ]) 
  then 
   FILE_NAME=/etc/pam.d/common-password 
   cat $FILE_NAME|egrep -v '^#'|egrep -v '^$'|egrep password --color=never
   str1=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep password --color=never |egrep sufficient`
   str2=`echo "$str1"|egrep "(.*)password(\s)+sufficient(\s)+pam_unix.so(.*)remember=([5-9]|([1-9][0-9]+))(.*)"`
   if [ -n "$str1" ];
		then if [ -n "$str2" ];
				then echo "OS_Linux_32 口令重复次数合规";
				else cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
				sed -i 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/common-password ;
				echo "OS_Linux_32 口令重复次数不合规"
				fi;
		else 
		cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
		echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5">> /etc/pam.d/common-password ;
		echo "OS_Linux_32 口令重复次数不合规"
	fi;
   else 
  if [ -f /etc/SuSE-release ] 
  then 
  FILE_NAME=/etc/pam.d/passwd 
  cat $FILE_NAME|egrep -v '^#'|egrep -v '^$'|egrep password --color=never 
  str1=`cat $FILE_NAME |sed '/^#/d'|sed '/^$/d'|egrep password --color=never|egrep sufficient`
  str2=`echo "$str1"|egrep "(.*)password(\s)+sufficient(\s)+pam_unix.so(.*)remember=([5-9]|([1-9][0-9]+))(.*)"`
  if [ -n "$str1" ];
		then if [ -n "$str2" ];
				then echo "OS_Linux_32 口令重复次数合规";
				else cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
				sed -i 's/password    sufficient    pam_unix.so.*/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/passwd ;
				echo "OS_Linux_32 口令重复次数不合规"
				fi;
		else 
		cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth.bak
		echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5">> /etc/pam.d/passwd ;
		echo "OS_Linux_32 口令重复次数不合规"
	fi;
  fi 
fi
unset suse_version FILE_NAME;
