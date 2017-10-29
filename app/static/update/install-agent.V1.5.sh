#!/bin/sh
#用途：用于各linux系统下自动安装zabbix-agnet
#适用操作系统：Centos Ubuntu Freebsd Ecool SUSE
#日期：2016年04月20日
#编写人：温永鑫
#版本号：V1.4

ZABBIX="/usr/local/zabbix/sbin/zabbix_agentd"
ZABBIX_DIR=`pwd`
system=$1
public=$2
proxy_info(){
	echo -e "\033[49;32;1m 中国香港		103.227.128.16 \033[0m"
	echo -e "\033[49;32;1m 腾 讯 云		119.29.137.171 \033[0m"
        echo -e "\033[49;32;1m 台湾远传		218.32.219.148 \033[0m"
        echo -e "\033[49;32;1m 台湾中华		203.69.109.117 \033[0m"
        echo -e "\033[49;32;1m 韩    国		58.229.180.29 \033[0m"
        echo -e "\033[49;32;1m 东 南 亚		175.41.130.249 \033[0m"
        echo -e "\033[49;32;1m 欧    洲		54.93.169.149 \033[0m"
        echo -e "\033[49;32;1m 美    洲		54.207.73.140 \033[0m"
        echo -e "\033[49;32;1m 悉    尼		54.206.96.244 \033[0m"
}

system_info(){
	echo "系统类型：Centos  c , Ubuntu  u , Debian d , Freebsd  f , Ecool  e , SUSE  s"
}

install_info(){
	echo
	echo -e "-------------------\033[49;31;1m Information \033[0m------------------------"
	echo "该脚本可通过批量安装脚本执行安装，按照其脚本命令要求即可"
        echo "该脚本可单独执行适合于以下几种情况："
        echo "1、被监控机只有内网IP没有公网IP地址。"
        echo "2、必须选择对应的proxy地址，否则无法继续安装。"
	echo "考虑到在使用中会忘记对应信息的情况。这里可以直接交互式处理"
	echo "如果\$1位置未填写，则会提醒输入对应的系统简写。"
	echo "如果\$2位置未填写，则会系统自动匹配IP地址，无需人工处理。"
	echo "但是这点得注意，适合能够通过ifconfig命令看到公网IP的，如果是无法看到的要加入公网IP地址"
	echo "如果\$3位置未填写，则会提醒各proxy的信息。这里需要输入ip地址"
	echo "-------------------------------------------------------"
	use="\033[49;32;1m $0 <系统简写> <本机公网IP> <proxy的IP地址> \033[0m"
	echo -e $use
	echo
}

select_ip(){
	ifconfig > /dev/null 2>&1
	if [ $? -ne 0 ];then
		yum -y install net-tools > /dev/null 2>&1 && echo "This system is centos 7"
	fi
        IPADD=`ifconfig | awk '/inet /{gsub(/addr:/,"");print $2}' | grep -v '127.0.0.1'`
        address=`echo -n $IPADD | awk '{print $1}'`
}

if [ "$1" == "-h" ];then
	install_info
	exit
elif [ -s $1 ];then
	system_info
	read -p "Please input your install the system: " system	
fi

if [ -z $2 ];then
	select_ip
else
	echo $2 | grep "^[0-9]\{1,3\}\.\([0-9]\{1,3\}\.\)\{2\}[0-9]\{1,3\}$" > /dev/null 2>&1
	if [ $? -eq 0 ];then
	        address=$2
		public=$address
	else
		select_ip
	fi
fi

if [ -z $3 ];then
	proxy_info
	read -p "Please input proxy ip address: " proxy_ip
else
	proxy_ip=$3

fi

if [ -z $public ];then
        public=$address
fi

echo "---------------------------------------------------"
echo $0 $system $address $proxy_ip
echo "---------------------------------------------------"


KEY(){
	[ -d /usr/local/zabbix/scripts ] 
	if [ $? -ne 0 ] ; then 
		mkdir /usr/local/zabbix/scripts
	fi
	tar -xf ./port.tar -C /usr/local/zabbix/scripts/
	[ $? -eq 0 ] && mv /usr/local/zabbix/scripts/my.cnf /usr/local/zabbix/scripts/.my.cnf
	[ $? -eq 0 ] && chmod a+x /usr/local/zabbix/scripts/*.sh
	[ $? -eq 0 ] && tar -xf ../key.tar -C /usr/local/zabbix/etc/zabbix_agentd.conf.d/
}


INSTALL_PT(){
	wget http://218.32.219.148:8080/pt/key-pt.tar > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m key-pt.tar is down"
	[ $? -eq 0 ] && wget http://218.32.219.148:8080/pt/log_scripts.tar.gz  > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m key-pt.tar is down"
	[ $? -eq 0 ] && tar xf key-pt.tar -C /usr/local/zabbix/etc/zabbix_agentd.conf.d  > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m is key-pt ok"
	[ $? -eq 0 ] && tar xf log_scripts.tar.gz -C /usr/local/zabbix/scripts  > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m log_scripts is ok"
	[ $? -eq 0 ] && chown zabbix. /usr/local/zabbix/scripts/*
	[ $? -eq 0 ] && chmod +x /usr/local/zabbix/scripts/*
	[ $? -eq 0 ] && rm -rf $ZABBIX_DIR/key-pt.tar > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m key-pt.tar id delete"
	[ $? -eq 0 ] && rm -rf $ZABBIX_DIR/log_scripts.tar.gz > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m key-pt.tar id delete"
}

INSTALL_AGENT(){
	tar -xf ./zabbix-2.4.4.tar.gz > /dev/null 2>&1
	[ $? -eq 0 ] && cd zabbix-2.4.4 
	[ $? -eq 0 ] && ./configure --prefix=/usr/local/zabbix --enable-agent  > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Install Agent" 
	[ $? -eq 0 ] && make > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Make ok"
	[ $? -eq 0 ] && make install > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Install ok"
	[ $? -eq 0 ] && mv $ZABBIX_DIR/zabbix_agentd.conf /usr/local/zabbix/etc/zabbix_agentd.conf 
	[ $? -eq 0 ] && KEY && echo -e "\033[49;32;1m $public \033[0m KEY is Upload.."
	[ $? -eq 0 ] && if [ "$system" == "c" ];then
				INSTALL_PT
			fi
	[ $? -eq 0 ] && if [ "$system" == "f" ];then
  				sed -i "" "s/Hostname=8.8.8.8/`echo Hostname=$public`/g" /usr/local/zabbix/etc/zabbix_agentd.conf
				[ $? -eq 0 ] && sed -i i"" "s/8.8.4.4/$proxy_ip:10928/g" /usr/local/zabbix/etc/zabbix_agentd.conf
			else 
				sed -i "s/Hostname=8.8.8.8/`echo Hostname=$public`/g" /usr/local/zabbix/etc/zabbix_agentd.conf 
				[ $? -eq 0 ] && sed -i "s/8.8.4.4/$proxy_ip:10928/g" /usr/local/zabbix/etc/zabbix_agentd.conf
			fi
	[ $? -eq 0 ] && /usr/local/zabbix/sbin/zabbix_agentd && echo -e "\033[49;32;1m $public \033[0m Zabbix-Agent is Running"
}

DOWN(){
	wget http://218.32.219.148:8080/client/key.tar > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m key.tar is ok"
	[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/net-snmp-5.7.2.tar.gz > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m net-snmp-5.7.2.tar.gz is ok"
	[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/port.tar > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m port.tar is ok"
	[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/zabbix-2.4.4.tar.gz > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m zabbix-2.4.4.tar.gz is ok"
	[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/zabbix_agentd.conf > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m zabbix_agentd.conf is ok"
}

DELE(){
	rm -rf $ZABBIX_DIR/key.tar && echo -e "\033[49;32;1m $public \033[0m Delete key.tar"
	[ $? -eq 0 ] && rm -rf $ZABBIX_DIR/port.tar && echo -e "\033[49;32;1m $public \033[0m Delete port.tar"
	[ $? -eq 0 ] && rm -rf $ZABBIX_DIR/net-snmp-5.7.2* && echo -e "\033[49;32;1m $public \033[0m Delete net-snmp"
	[ $? -eq 0 ] && rm -rf $ZABBIX_DIR/zabbix-2.4.4* && echo -e "\033[49;32;1m $public \033[0m Delete zabbix"
}

SNMP(){
	tar -xf net-snmp-5.7.2.tar.gz
	[ $? -eq 0 ] && cd net-snmp-5.7.2
	[ $? -eq 0 ] && ./configure --prefix=/usr/local/snmpd  <<EOF > /dev/null 2>&1 

2



EOF
	[ $? -eq 0 ] && echo -e "\033[49;32;1m $public \033[0m SNMP install"
	[ $? -eq 0 ] && make > /dev/null 2>&1 
	echo -e "\033[49;32;1m $public \033[0m Snmp Make ok"
	[ $? -eq 0 ] && make install > /dev/null 2>&1 
	echo -e "\033[49;32;1m $public \033[0m Snmp Make Install ok"
	[ $? -eq 0 ] && mv ../snmpd.conf /usr/local/snmpd/
	[ $? -eq 0 ] && /usr/local/snmpd/sbin/snmpd -c /usr/local/snmpd/snmpd.conf 
	echo -e "\033[49;32;1m $public \033[0m SNMP is Running...."
	[ $? -eq 0 ] && cd $ZABBIX_DIR
}

INIT(){
                U=`grep -E "zabbix|snmp" $RC | wc -l`
                if [ $U -ne 2 ] ; then 
                        echo $ZABBIX >> $RC
			echo $SNMP2 >> $RC
                else
			echo -e "\033[49;32;1m $public \033[0m Zabbix has been added to the boot.."
                fi
}

iptables_cmd(){
	echo "==============  $public iptables ============" 
	if [ ! -f "/tmp/iptable" ]; then
		if [ -f "/etc/sysconfig/iptables" ];then
			/etc/init.d/iptables status > /dev/null 2>&1
			if [ $? -eq 0 ];then
				wget -P $ZABBIX_DIR http://218.32.219.148:8080/client/iptables_comd.txt > /dev/null 2>&1
				while read iptable;do
					$iptable
				done < $ZABBIX_DIR/iptables_comd.txt
				/etc/init.d/iptables save
				rm -rf $ZABBIX_DIR/iptables_comd.txt
				echo -e "\033[49;32;1m $public \033[0m iptables is OK"
				touch /tmp/iptable > /dev/null 2>&1
			else
				wget -P $ZABBIX_DIR http://218.32.219.148:8080/client/iptables_conf.txt > /dev/null 2>&1
				while read iptable;do
					sed -i "/OUTPUT/a $iptable" /etc/sysconfig/iptables
				done < $ZABBIX_DIR/iptables_conf.txt
				rm -rf $ZABBIX_DIR/iptables_conf.txt
				echo -e "\033[49;32;1m $public \033[0m iptables is ok"
				touch /tmp/iptable > /dev/null 2>&1
			fi
		else
			echo -e "\033[49;31;1m $public No Find /etc/sysconfig/iptables \033[0m"
		fi
	else
		echo -e "\033[49;31;1m $public Firewall policy to exist \033[0m"
	fi
}

Centos6(){
        /etc/init.d/snmpd restart > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is up"
        [ $? -eq 0 ] && chkconfig snmpd on && echo -e "\033[49;32;1m $public \033[0m SNMP already boot"
}

Centos7(){
        /bin/systemctl restart snmpd > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is up"
        [ $? -eq 0 ] && /bin/systemctl enable snmpd > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP already boot"
	chmod +x /etc/rc.d/rc.local
}

case "$system" in
#centos/redhat
	c )
		echo "==== $public install software ====" 
		yum -y install gcc make > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Gcc and Make is Install"
		yum -y install file > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m File is Install"
		yum -y install perl-devel > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Perl-devel is Install"
		yum -y install openssh-clients > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m openssh-clients is Install"
		yum -y install sysstat > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m iostat is Install"
		yum -y install wget > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m wget is Install"
		useradd -M -s /sbin/nologin zabbix
		echo "=========== $public Download File ==========" 
		DOWN
		echo "=========== $public Install SNMP ============" 
		yum -y install net-snmp > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is Install"
		[ $? -eq 0 ] && yum -y install net-snmp-utils > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m snmpwalk is install"
		[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/snmpd.conf.yum > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m snmpd.conf is ok"
		[ $? -eq 0 ] && mv ./snmpd.conf.yum /etc/snmp/snmpd.conf && echo -e "\033[49;32;1m $public \033[0m SNMP file update is ok"
		Verson=`cat /etc/redhat-release | awk -F 'release' '{print $NF}' | awk -F '.' '{print $1}'`	
		if [ $Verson -eq 7 ];then
			Centos7
		else
			Centos6
			iptables_cmd
		fi
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/rc.d/rc.local 
		INIT
		echo "======= $public Delete down file ==========" 
		DELE
	;;
#ubuntu
	u )
		echo "==== $public install software ====" 
		var=`cat /etc/issue | awk '{print $2}' | awk -F '.' '{print $1}'`
		if [ $var -eq 12 ];then
			rm -rf /var/lib/apt/lists/*
		fi
		apt-get -y update > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Apt is Update"
		apt-get -y install gcc > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Gcc is Install"
		apt-get -y install make > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Make is Install"
		apt-get -y install libperl-dev > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Libperl is Install"
		useradd -M -s /sbin/nologin zabbix
		echo "=========== $public Download File ==========" 
		DOWN
		echo "=========== $public Install SNMP ============" 
		apt-get -y install snmpd snmp > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is Install"
		[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/snmpd.conf > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Down snmpd.conf ok"
		[ $? -eq 0 ] && mv ./snmpd.conf /etc/snmp/snmpd.conf && echo -e "\033[49;32;1m $public \033[0m SNMP file update is ok"
		[ $? -eq 0 ] && /etc/init.d/snmpd restart > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is UP"
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/rc.local
		SNMP2="service snmpd start"
		sed -i "/exit 0/"d $RC
		INIT
		echo "exit 0" >> $RC
		echo -e "======= \033[49;32;1m $public \033[0m Delete down file =========="
                DELE
	;;
	d )
		echo "==== $public install software ====" 
		rm -rf /var/cache/apt/archives/lock
		rm -rf /var/lib/dpkg/lock
		source="deb http://http.us.debian.org/debian/ stable main"
		sed -i "s/^/#/g" /etc/apt/sources.list
		sed -i "2 s#^#$source\n#" /etc/apt/sources.list
		apt-get -y update > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Apt is Update"
		apt-get -y install gcc > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Gcc is Install"
		apt-get -y install make > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Make is Install"
		apt-get -y install libperl-dev <<EOF > /dev/null 2>&1
q
EOF
		useradd -M -s /sbin/nologin zabbix
		echo "=========== $public Download File ==========" 
		wget http://218.32.219.148:8080/client/snmpd.conf > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Down snmpd.conf ok"
		DOWN
		echo "=========== $public Install SNMP ============" 
		SNMP
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/rc.local
		SNMP2="service snmpd start"
		sed -i "/exit 0/"d $RC
		INIT
		echo "exit 0" >> $RC
		echo -e "======= \033[49;32;1m $public \033[0m Delete down file =========="
                DELE
	;;
#freebsd
	f )
		echo "==== $public install libiconv====" 
		pkg_add http://218.32.219.148:8080/client/pack_freebsd/perl-5.14.4.tbz > /dev/null 2>&1 && echo "$public perl is install"
		[ $? -eq 0 ] && pkg_add http://218.32.219.148:8080/client/pack_freebsd/net-snmp.tbz > /dev/null 2>&1 && echo "$public net-snmp is install"
		echo "================= $public Install End ======================" 
		pw user add zabbix -s /sbin/nologin
		echo "=========== $public Download File ==========" 
                DOWN
		echo "=========== $public Install SNMP ============" 
		wget http://218.32.219.148:8080/client/snmpd.conf > /dev/null 2>&1 && echo "$public Down snmpd.conf ok"
		[ $? -eq 0 ] && mv ./snmpd.conf /usr/local/etc/snmpd.conf && echo "$public SNMP file update is ok"
		[ $? -eq 0 ] && echo "snmpd_conffile="/usr/local/etc/snmpd.conf"" >> /etc/rc.conf 
		[ $? -eq 0 ] && echo "snmpd_enable="YES"" >> /etc/rc.conf
		[ $? -eq 0 ] && /usr/local/etc/rc.d/snmpd restart && echo "$public SNMP already boot" 
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/rc.local
		SNMP2="/usr/local/etc/rc.d/snmpd start"
		[ -f $RC ]
		if [ $? -ne 0 ] ; then
			echo "#!/bin/sh" > $RC
		fi
		INIT
		echo "======= $public Delete down file ==========" 
                DELE
	;;
#ecool
	e )
		useradd -M -s /sbin/nologin zabbix
		echo "=========== $public Download File ==========" 
		wget http://218.32.219.148:8080/client/snmpd.conf > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Down snmpd.conf ok"
                DOWN
		echo "=========== $public Install SNMP ============" 
		SNMP
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/rc.d/rc.local
		SNMP2="/usr/local/snmpd/sbin/snmpd -c /usr/local/snmpd/snmpd.conf"
		INIT
		echo "======= $public Delete down file ==========" 
                DELE
	;;
#suse
	s )
		zypper install -y gcc > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Gcc is Install"
		useradd -M -s /sbin/nologin zabbix
		echo "=========== $public Download File ==========" 
                DOWN
		echo "=========== $public Install SNMP ============" 
		zypper install -y net-snmp > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is Install"
		[ $? -eq 0 ] && wget http://218.32.219.148:8080/client/snmpd.conf > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m Down snmpd.conf ok"
                [ $? -eq 0 ] && mv ./snmpd.conf /etc/snmp/snmpd.conf && echo -e "\033[49;32;1m $public \033[0m SNMP file update is ok"
                [ $? -eq 0 ] && /etc/init.d/snmpd restart > /dev/null 2>&1 && echo -e "\033[49;32;1m $public \033[0m SNMP is up"
                [ $? -eq 0 ] && chkconfig snmpd on && echo -e "\033[49;32;1m $public \033[0m SNMP already boot"
		echo "=========== $public Install Agent ==========" 
		INSTALL_AGENT
		RC=/etc/init.d/after.local
		[ -f $RC ]
		if [ $? -ne 0 ] ; then
			echo "#!/bin/sh" > $RC
		fi
		INIT
		echo "======= $public Delete down file ==========" 
                DELE
	;;
esac
