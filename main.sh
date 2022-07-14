#!/bin/bash
echo "=======================   -cPanel server installation and configuration-  ======================="

pwdir=$(pwd)
cd $pwdir

# yum update -y
# yum install epel-release -y
# yum install vim screen -y

# Setting up Hostname and hosts file
server_ip=$( hostname -I | awk '{print $1}' )
read -e -p "Enter hostname: "  host_name
hostnamectl set-hostname $host_name
host=$( echo $host_name | cut -d"." -f1 )
sed -i '$ d' /etc/hosts # It will remove last line of /etc/hosts file
echo $server_ip $host_name $host >> /etc/hosts
name_server=$( hostname -d )



# Basic Server Setup
# ref link: https://docs.cpanel.net/installation-guide/customize-your-installation/?_ga=2.157169467.1496637653.1653812559-33349048.1652956930
cat > /etc/wwwacct.conf << EOF
ADDR $server_ip
DEFMOD jupiter
HOMEDIR /home
LOGSTYLE combined
NS ns1.$name_server
NS2 ns2.$name_server
TTL 14400
NSTTL 86400
SCRIPTALIAS y
CONTACTEMAIL vps@serversea.com
EOF


mkdir /root/cpanel_profile
touch /root/cpanel_profile/cpanel.config
echo "mysql-version=10.5" > /root/cpanel_profile/cpanel.config


# Creating EasyApache Profile
linuxos=$(cat /etc/centos-release | cut -f1 -d" ")

if [ "$linuxos" == "AlmaLinux" ]
then
cp ./almalinux.json /etc/cpanel_initial_install_ea4_profile.json
else
cp ./centos7.json /etc/cpanel_initial_install_ea4_profile.json
fi

# Installing cPanel
cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest

cd $pwdir

############ PHP Configuration ############

configurePHP () {
	# Example ea-phpXX file location
	# /opt/cpanel/ea-php72/root/etc/php.ini
	EA_PHP_FILES=( /opt/cpanel/ea-php*/root/etc/php.ini )
	sed -i -e 's/disable_functions =.*/disable_functions = dl, exec, phpinfo, shell_exec, system, passthru, popen, pclose, proc_open, proc_nice, proc_terminate, proc_get_status, proc_close, pfsockopen, leak, apache_child_terminate, posix_kill, posix_mkfifo, posix_setpgid, posix_setsid, posix_setuid, eval, gzinflate/g' "${EA_PHP_FILES[@]}"
	sed -i -e 's/post_max_size = 8M/post_max_size = 128M/g' "${EA_PHP_FILES[@]}"
	sed -i -e 's/upload_max_filesize = 2M/upload_max_filesize = 128M/g' "${EA_PHP_FILES[@]}"
	sed -i -e 's/max_execution_time = 30/max_execution_time = 300/g' "${EA_PHP_FILES[@]}"
	sed -i -e 's/max_input_time = 60/max_input_time = 600/g' "${EA_PHP_FILES[@]}"
	sed -i -e 's/memory_limit = 32M/memory_limit = 256M/g' "${EA_PHP_FILES[@]}"
}


############ SSH Configuration ############

configureSSH () {
    sed -i -e 's/Port 22/Port 22433/g' /etc/ssh/sshd_config
	sed -i -e 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
	check=$( grep "UseDNS no" /etc/ssh/sshd_config  )
	if [ "$check" == "UseDNS no" ]
	then
	echo "Already exists, no need to modify"
	else
	echo "UseDNS no" >> /etc/ssh/sshd_config
	echo "sshd_config modified"
	fi
	chattr +ia /etc/ssh/sshd_config
    mkdir /root/.ssh &> /dev/null
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCPYOMcJXOtr6DAhHbqQjNP9+iXDV1LZKKKgqozcYwVzcmeWmWmkWO78i0XmVVMOYMA8Kw9RtF2DitLEqrn4P18wmniP8h8kugqA5icFTTPQl+D0bXaJogAwROkJeFGNTKS83ZfSv08bIRdIW2TZAP1i8uu4fggXb/oSS/7mBfMiB8dB5H7rBkvGFbbObz+WTZZSTVs+PABVnFkcD4/WVZqLkuK0l+u41tnFyJmfswLgG+Hme3RvyHwDTjCZNRy9bXKI2CtY1RsBrmakvB4L8vB+M7lp/O61aQXgvk4b5eSx4Dz1v5qCBlv+RbQgKSRnTtnvCC53i8tB0UTsEHjlRj5 ss-vps' > /root/.ssh/authorized_keys
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArzmgdDUDO6QTaeqiaqomdchiWNu4EUZa5NxwfIBbXT+Ue0S9M2UENQlVXeK/6Ywrpc1ej7Le8jyGrDsfShwTyH6Z/c7Ea8fK4cPN55cf7UxJaIl0llWYigTSQVyou6MojU6yeKOa6TWOCCwkZFy2uX2WHsqzPGZ1kqnYhCyv3WiXJnegJqcr37NXg3zf+u8CFudXa2Feei9WpZOQqU0sRF2WxdHaydFtStifkmagjatinZkuxl2Nkh0kz/FdZD+R0sUNm8yCfZ756Q1n5ETCyMI6HljF6ECmm1hPe3F1a9aUdgt934YbTdZ7+vO6Km0OFszWVomXHku+cI+23UJNXQ==  SSVPS20151221' >> /root/.ssh/authorized_keys

	chattr -R +ia /root/.ssh
    systemctl restart sshd
}


############ Installation and configuration of CSF ############

installCSF () {
	wget https://download.configserver.com/csf.tgz 
	tar -xzf csf.tgz
	cd csf
	./install.sh
	cd ../
	sed -i -e 's/LF_SSHD = "5"/LF_SSHD ="30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_FTPD = "10"/LF_FTPD = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_SMTPAUTH = "5"/LF_SMTPAUTH = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_EXIMSYNTAX = "10"/LF_EXIMSYNTAX = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_POP3D = "10"/LF_POP3D = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_IMAPD = "10"/LF_IMAPD = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_HTACCESS = "5"/LF_HTACCESS = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/LF_CPANEL = "5"/LF_CPANEL = "30"/g' /etc/csf/csf.conf
	sed -i -e 's/TESTING = "1"/TESTING = "0"/g' /etc/csf/csf.conf
	csf -r
}


configurePHP
configureSSH
installCSF

systemctl stop rpcbind &&  systemctl disable rpcbind


cat > /etc/sysctl.conf << EOF
kernel.panic = 10
kernel.watchdog_thresh = 20
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl -p


cat ./disabled_features.txt > /var/cpanel/features/disabled


# Install linux malware detecter (LMD)
# ref link:	https://www.rfxn.com/projects/linux-malware-detect/
wget https://www.rfxn.com/downloads/maldetect-current.tar.gz
tar -xzf maldetect-current.tar.gz
rm -rf maldetect-current.tar.gz
cd maldetect*
./install.sh

cd ../
cat ./conf.maldet > /usr/local/maldetect/conf.maldet

# Malware monitoring using LMD
yum install inotify-tools -y
maldet -u -m users


# SSH Banner
cat > /etc/motd << EOF
   _____ __________ _    ____________  _____ _________ 
  / ___// ____/ __ \ |  / / ____/ __ \/ ___// ____/   |
  \__ \/ __/ / /_/ / | / / __/ / /_/ /\__ \/ __/ / /| |
 ___/ / /___/ _, _/| |/ / /___/ _, _/___/ / /___/ ___ |
/____/_____/_/ |_| |___/_____/_/ |_|/____/_____/_/  |_|
                                                       

Welcome!

This server is hosted by ServerSea Hosting. If you have any questions or need help,
please don't hesitate to contact us at support@serversea.com

EOF

hostnamectl set-hostname $host_name

echo "=======================Congratulations! Server Configuration is completed ======================="
echo "======================= SYSTEM WILL REBOOT AFTER One MINUTE ======================"
