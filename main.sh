#!/bin/bash
echo "=======================   -cPanel server installation and configuration-  ======================="

pwdir=$(pwd)
cd $pwdir

yum update -y

# yum install epel-release -y
# yum install vim screen -y

## Setting up Hostname and hosts file
server_ip=$( hostname -I | awk '{print $1}' )
read -e -p "Enter hostname: "  host_name
hostnamectl set-hostname $host_name
host=$( echo $host_name | cut -d"." -f1 )
sed -i '$ d' /etc/hosts # It will remove last line of /etc/hosts file
echo $server_ip $host_name $host >> /etc/hosts
name_server=$( hostname -d )



############# Basic Server Setup #############
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



############# Creating EasyApache Profile ############
linuxos=$(cat /etc/centos-release | cut -f1 -d" ")

if [ "$linuxos" == "AlmaLinux" ]
then
cp ./almalinux.json /etc/cpanel_initial_install_ea4_profile.json
else
cp ./centos7.json /etc/cpanel_initial_install_ea4_profile.json
fi


############# Installing cPanel  #############
cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest

cd $pwdir

############ cPanel Configuration ############

cpanelCONFIG () {
	# Disabling Compilers
	/scripts/compilers off
	
	
	# Enable Shell Fork Bomb Protection
	# ref link https://www.siliconhouse.net/support/shell-fork-bomb-protection/
	perl -I/usr/local/cpanel -MCpanel::LoginProfile -le 'print [Cpanel::LoginProfile::install_profile('limits')]->[1];'
	systemctl restart cpanel
	

	# disable cphulk brute force 
	# ref link https://docs.cpanel.net/knowledge-base/security/cphulk-management-on-the-command-line/
	whmapi1 configureservice service=cphulkd enabled=0 monitored=0
	/usr/local/cpanel/etc/init/stopcphulkd
	/usr/local/cpanel/bin/cphulk_pam_ctl --disable
	
	
	# setting password strength to 100%
	# ref link https://forums.cpanel.net/threads/setting-minimum-password-strenght-via-script.407992/
	sed -i 's/minpwstrength=65/minpwstrength=100/g' /var/cpanel/cpanel.config
	
	
	# Changing apache mpm from prefork to event
	# ref link https://support.cpanel.net/hc/en-us/articles/4406506158231-How-to-change-your-Apache-MPM
	#yum remove ea-apache24-mod_mpm_prefork -y
	#yum remove remove ea-apache24-mod_cgi -y
	#yum install ea-apache24-mod_mpm_event -y
	
	# Installing php versions and extensions
	# yum install ea-apache24 ea-apache24-config ea-apache24-config-runtime ea-apache24-mod_asis ea-apache24-mod_auth_digest ea-apache24-mod_authn_anon ea-apache24-mod_authn_socache ea-apache24-mod_authz_dbm ea-apache24-mod_bwlimited ea-apache24-mod_cgid ea-apache24-mod_deflate ea-apache24-mod_expires ea-apache24-mod_headers ea-apache24-mod_mpm_event ea-apache24-mod_proxy ea-apache24-mod_proxy_http ea-apache24-mod_proxy_wstunnel ea-apache24-mod_remoteip ea-apache24-mod_security2 ea-apache24-mod_ssl ea-apache24-mod_suexec ea-apache24-mod_suphp ea-apache24-mod_unique_id ea-apache24-mod_usertrack ea-apache24-mod_version ea-apache24-mod_watchdog ea-apache24-tools ea-apr ea-apr-util ea-brotli ea-cpanel-tools ea-documentroot ea-libargon2 ea-libcurl ea-libicu ea-libmcrypt ea-libnghttp2 ea-libnghttp2-devel ea-libtidy ea-libxml2 ea-libzip ea-modsec-sdbm-util ea-nghttp2 ea-oniguruma ea-oniguruma-devel ea-openssl ea-openssl-devel ea-openssl11 ea-openssl11-devel ea-php-cli ea-php-cli-lsphp ea-php70 ea-php70-libc-client ea-php70-pear ea-php70-php-bcmath ea-php70-php-calendar ea-php70-php-cli ea-php70-php-common ea-php70-php-curl ea-php70-php-devel ea-php70-php-fileinfo ea-php70-php-ftp ea-php70-php-gd ea-php70-php-gettext ea-php70-php-iconv ea-php70-php-imap ea-php70-php-intl ea-php70-php-ioncube10 ea-php70-php-litespeed ea-php70-php-mbstring ea-php70-php-mcrypt ea-php70-php-mysqlnd ea-php70-php-opcache ea-php70-php-pdo ea-php70-php-posix ea-php70-php-soap ea-php70-php-sockets ea-php70-php-xml ea-php70-php-zip ea-php70-runtime ea-php71 ea-php71-libc-client ea-php71-pear ea-php71-php-bcmath ea-php71-php-calendar ea-php71-php-cli ea-php71-php-common ea-php71-php-curl ea-php71-php-devel ea-php71-php-fileinfo ea-php71-php-ftp ea-php71-php-gd ea-php71-php-gettext ea-php71-php-iconv ea-php71-php-imap ea-php71-php-intl ea-php71-php-ioncube10 ea-php71-php-litespeed ea-php71-php-mbstring ea-php71-php-mcrypt ea-php71-php-mysqlnd ea-php71-php-pdo ea-php71-php-posix ea-php71-php-soap ea-php71-php-sockets ea-php71-php-xml ea-php71-php-zip ea-php71-runtime ea-php72 ea-php72-libc-client ea-php72-pear ea-php72-php-bcmath ea-php72-php-calendar ea-php72-php-cli ea-php72-php-common ea-php72-php-curl ea-php72-php-devel ea-php72-php-fileinfo ea-php72-php-ftp ea-php72-php-gd ea-php72-php-gettext ea-php72-php-iconv ea-php72-php-imap ea-php72-php-intl ea-php72-php-ioncube10 ea-php72-php-litespeed ea-php72-php-mbstring ea-php72-php-mysqlnd ea-php72-php-pdo ea-php72-php-posix ea-php72-php-soap ea-php72-php-sockets ea-php72-php-xml ea-php72-php-zip ea-php72-runtime ea-php73 ea-php73-libc-client ea-php73-pear ea-php73-php-bcmath ea-php73-php-calendar ea-php73-php-cli ea-php73-php-common ea-php73-php-curl ea-php73-php-devel ea-php73-php-fileinfo ea-php73-php-ftp ea-php73-php-gd ea-php73-php-gettext ea-php73-php-iconv ea-php73-php-imap ea-php73-php-intl ea-php73-php-ioncube10 ea-php73-php-litespeed ea-php73-php-mbstring ea-php73-php-mysqlnd ea-php73-php-pdo ea-php73-php-posix ea-php73-php-soap ea-php73-php-sockets ea-php73-php-xml ea-php73-php-zip ea-php73-runtime ea-php74 ea-php74-libc-client ea-php74-pear ea-php74-php-bcmath ea-php74-php-calendar ea-php74-php-cli ea-php74-php-common ea-php74-php-curl ea-php74-php-devel ea-php74-php-ftp ea-php74-php-gd ea-php74-php-gettext ea-php74-php-iconv ea-php74-php-imap ea-php74-php-intl ea-php74-php-litespeed ea-php74-php-mbstring ea-php74-php-mysqlnd ea-php74-php-pdo ea-php74-php-posix ea-php74-php-sockets ea-php74-php-xml ea-php74-php-zip ea-php74-runtime ea-php80 ea-php80-libc-client ea-php80-pear ea-php80-php-bcmath ea-php80-php-calendar ea-php80-php-cli ea-php80-php-common ea-php80-php-curl ea-php80-php-devel ea-php80-php-ftp ea-php80-php-gd ea-php80-php-gettext ea-php80-php-iconv ea-php80-php-imap ea-php80-php-intl ea-php80-php-litespeed ea-php80-php-mbstring ea-php80-php-mysqlnd ea-php80-php-pdo ea-php80-php-posix ea-php80-php-sockets ea-php80-php-xml ea-php80-php-zip ea-php80-runtime ea-php81 ea-php81-libc-client ea-php81-pear ea-php81-php-bcmath ea-php81-php-calendar ea-php81-php-cli ea-php81-php-common ea-php81-php-curl ea-php81-php-devel ea-php81-php-ftp ea-php81-php-gd ea-php81-php-gettext ea-php81-php-iconv ea-php81-php-imap ea-php81-php-intl ea-php81-php-litespeed ea-php81-php-mbstring ea-php81-php-mysqlnd ea-php81-php-pdo ea-php81-php-posix ea-php81-php-sockets ea-php81-php-xml ea-php81-php-zip ea-php81-runtime ea-profiles-cpanel -y
	
	
	# Installing mariadb version 10.5
	# upgrading mysql 
	# ref link https://www.digitalocean.com/community/questions/update-mysql-version-cpanel-whm-using-api-command-line-terminal
	# whmapi1 start_background_mysql_upgrade version=10.5
	
	
	# Installing pure FTP
	/usr/local/cpanel/scripts/setupftpserver pure-ftpd
	
	# Disabling SSH Terminal GUI
	touch /var/cpanel/disable_whm_terminal_ui
	chattr +ia /var/cpanel/disable_whm_terminal_ui
	
	
	# Apache mod_userdir Tweak
	echo "UserDir disabled" > /etc/apache2/conf.d/includes/post_virtualhost_global.conf
	
	
	# Apache global configuration
	# ref link: https://docs.cpanel.net/whm/service-configuration/global-configuration/
	sed -i -e 's/.*root_options.*/   "root_options" : "SymLinksIfOwnerMatch IncludesNOEXEC ExecCGI",/g' /etc/cpanel/ea4/ea4.conf
	sed -i -e 's/.*symlink_protect.*/   "symlink_protect" : "On",/g' /etc/cpanel/ea4/ea4.conf
	# Now rebuild configuration and restart apache
	# ref link: https://docs.cpanel.net/whm/scripts/the-rebuildhttpdconf-script/
	/usr/local/cpanel/scripts/rebuildhttpdconf
	/usr/local/cpanel/scripts/restartsrv_httpd
	
	
	# Disable Traceroute
	chmod 700 /bin/traceroute
	
	# cpanel harden script
	# https://github.com/tripflex/cpsetup/blob/master/cpsetup

}



############ PHP Configuration #############
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
    sed -i -e 's/#Port 22/Port 22433/g' /etc/ssh/sshd_config
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


############ Configure FTP Server ############
configureftp () {
	echo "ForcePassiveIP: ~" > /var/cpanel/conf/pureftpd/local
	echo "PassivePortRange: 49152 65534" >> /var/cpanel/conf/pureftpd/local
	/usr/local/cpanel/scripts/setupftpserver pure-ftpd --force
	sed -i -e 's/TCP_IN = "/TCP_IN = "49152:65534,/g' /etc/csf/csf.conf
	csf -r
}


cpanelCONFIG
configurePHP
configureSSH
installCSF
configureftp

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
