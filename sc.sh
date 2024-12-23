#!/bin/bash
clear
echo 'auto-updates && sources : software & updates'
grep ^ /etc/apt/sources.list /etc/apt/sources.list.d/*
_____-------________------_____------_____------______----
cat /etc/sudoers | grep 
_____-------_______-------_------______------________-------__
cat sleeping
sleep 90

startTime=$(date +"%s")
printTime()
{
	endTime=$(date +"%s")
	diffTime=$(($endTime-$startTime))
	if [ $(($diffTime / 60)) -lt 10 ]
	then
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		else
			echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	else
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log else
			echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	fi
}

touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

if [[ $EUID -ne 0 ]]
then
  echo This script must be run as root
  exit
fi
printTime "Script is being run as root."

printTime "The current OS is Linux Ubuntu."
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
printTime "Backups folder created on the Desktop."

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

printTime "/etc/group and /etc/passwd files backed up."

apt purge aisleriot -y
sudo chmod 640 /etc/shadow
sudo chmod 640 /etc/passwd
sudo chmod 640 /etc/group
sudo chmod 640 /etc/apt/sources.list

echo "APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"0\";
APT::Periodic::AutocleanInterval \"0\";" > /etc/apt/apt.conf.d/10periodic
echo "Checks for updates automatically"


echo Type all user account names, with a space in between
read -a users

apt-get update -y
apt-get dist-upgrade -y
apt-get install -f -y
apt-get autoremove -y
apt-get autoclean -y
apt-get check

usersLength=${#users[@]}	


for (( i=0;i<$usersLength;i++))
do
	clear
	echo ${users[${i}]}
	echo Delete ${users[${i}]}? yes or no
	read yn1
	if [ $yn1 == yes ]
	then
		userdel -r ${users[${i}]}
		printTime "${users[${i}]} has been deleted."

	else	
		echo Make ${users[${i}]} administrator? yes or no
		read yn2								
		if [ $yn2 == yes ]
		then
			gpasswd -a ${users[${i}]} sudo
			gpasswd -a ${users[${i}]} adm
			gpasswd -a ${users[${i}]} lpadmin
			gpasswd -a ${users[${i}]} sambashare
			printTime "${users[${i}]} has been made an administrator."
		else
			gpasswd -d ${users[${i}]} sudo
			gpasswd -d ${users[${i}]} adm
			gpasswd -d ${users[${i}]} lpadmin
			gpasswd -d ${users[${i}]} sambashare
			gpasswd -d ${users[${i}]} root
			printTime "${users[${i}]} has been made a standard user."
		fi
		
		echo Make custom password for ${users[${i}]}? yes or no
		read yn3								
		if [ $yn3 == yes ]
		then
			echo Password:
			read pw
			echo -e "$pw\n$pw" | passwd ${users[${i}]}
			printTime "${users[${i}]} has been given the password '$pw'."
		else
			echo -e "Moodle!22\nMoodle!22" | passwd ${users[${i}]}
			printTime "${users[${i}]} has been given the password 'Moodle!22'."
		fi
		passwd -x30 -n3 -w7 ${users[${i}]}
		usermod -L ${users[${i}]}
		printTime "${users[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
	fi
done
clear

echo Type user account names of users you want to add, with a space in between
read -a usersNew

usersNewLength=${#usersNew[@]}	

for (( i=0;i<$usersNewLength;i++))
do
	clear
	echo ${usersNew[${i}]}
	adduser ${usersNew[${i}]}
	printTime "A user account for ${usersNew[${i}]} has been created."
	clear
	echo Make ${usersNew[${i}]} administrator? yes or no
	read ynNew								
	if [ $ynNew == yes ]
	then
		gpasswd -a ${usersNew[${i}]} sudo
		gpasswd -a ${usersNew[${i}]} adm
		gpasswd -a ${usersNew[${i}]} lpadmin
		gpasswd -a ${usersNew[${i}]} sambashare
		printTime "${usersNew[${i}]} has been made an administrator."
	else
		printTime "${usersNew[${i}]} has been made a standard user."
	fi
	
	passwd -x30 -n3 -w7 ${usersNew[${i}]}
	usermod -L ${usersNew[${i}]}
	printTime "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
done

apt install resolvconf -y
systemctl enable --now resolvconf.service

find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete

	apt-get install -y iptables
	apt-get install -y iptables-persistent
	#Backup
	mkdir /iptables/
	touch /iptables/rules.v4.bak
	touch /iptables/rules.v6.bak
	iptables-save > /iptables/rules.v4.bak
	ip6tables-save > /iptables/rules.v6.bak
	#Clear out and default iptables
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -X
	iptables -t mangle -X
	iptables -F
	iptables -X
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t nat -X
	ip6tables -t mangle -X
	ip6tables -F
	ip6tables -X
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP
	#Block Bogons
	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
	read interface
	#Blocks bogons going into the computer
	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -s 0.0.0.0/8 -j DROP
	iptables -A INPUT -s 100.64.0.0/10 -j DROP
	iptables -A INPUT -s 169.254.0.0/16 -j DROP
	iptables -A INPUT -s 192.0.0.0/24 -j DROP
	iptables -A INPUT -s 192.0.2.0/24 -j DROP
	iptables -A INPUT -s 198.18.0.0/15 -j DROP
	iptables -A INPUT -s 198.51.100.0/24 -j DROP
	iptables -A INPUT -s 203.0.113.0/24 -j DROP
	iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -d 0.0.0.0/8 -j DROP
	iptables -A INPUT -d 100.64.0.0/10 -j DROP
	iptables -A INPUT -d 169.254.0.0/16 -j DROP
	iptables -A INPUT -d 192.0.0.0/24 -j DROP
	iptables -A INPUT -d 192.0.2.0/24 -j DROP
	iptables -A INPUT -d 198.18.0.0/15 -j DROP
	iptables -A INPUT -d 198.51.100.0/24 -j DROP
	iptables -A INPUT -d 203.0.113.0/24 -j DROP
	iptables -A INPUT -d 224.0.0.0/3 -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	#Least Strict Rules
	#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	#Strict Rules -- Only allow well known ports (1-1022)
	#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -o lo -j ACCEPT
	#iptables -P OUTPUT DROP
	#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -P OUTPUT DROP
	mkdir /etc/iptables/
	touch /etc/iptables/rules.v4
	touch /etc/iptables/rules.v6
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	cont
}
	printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
	#--------- Secure /etc/sysctl.conf ----------------
	sysctl -w net.ipv4.tcp_syncookies=1
	sysctl -w net.ipv4.ip_forward=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0
	sysctl -w net.ipv4.conf.all.secure_redirects=0
	sysctl -w net.ipv4.conf.default.secure_redirects=0
	sysctl -p
	cont

for i in $(grep ":0:" /etc/passwd | grep -v -e "root:x" -e "#"); do
	name=$(echo $i | cut -f1 -d: );
	echo $name
	#(deluser $name --remove-all-files  >> RemovingUsers.txt 2>&1) &    #Doesn’t work, as it fails and if you force it then it deletes root
	lineNumber=$(grep -in  -e $i /etc/passwd | cut -d: -f 1);
	sed -i '/'"$lineNumber"'/s/^/#/' /etc/passwd
	#These two actually find the line where the not root uid 0 is, and then comment that line out
	gnome-terminal -e "bash -c \"( echo "WARNING: THERE IS A HIDDEN ROOT USER ON THE COMPUTER. PLEASE RECTIFY THE SITUATION IMMEDIATELY."; exec bash )\"" & disown; sleep 2; 
	#This disown causes the terminal created to not be associated with the original terminal so when the original is closed it does not also close this one.
done

echo "Clearing HOSTS file"
#echo $(date): Clearing HOSTS file >> Warnings.txt
cp /etc/hosts hosts.bak
echo 127.0.0.1	localhost > /etc/hosts
echo 127.0.1.1	ubuntu  >> /etc/hosts

echo ::1     ip6-localhost ip6-loopback >> /etc/hosts
echo fe00::0 ip6-localnet >> /etc/hosts
echo ff00::0 ip6-mcastprefix >> /etc/hosts
echo ff02::1 ip6-allnodes >> /etc/hosts
echo ff02::2 ip6-allrouters >> /etc/hosts

for i in $(ls /var/spool/cron/crontabs); do
	cp /var/spool/cron/crontabs/$i $(pwd)/$i;
	rm /var/spool/cron/crontabs/$i;
done


echo Does this machine need Samba?
read sambaYN
echo Does this machine need FTP?
read ftpYN
echo Does this machine need SSH?
read sshYN
echo Does this machine need Telnet?
read telnetYN
echo Does this machine need Mail?
read mailYN
echo Does this machine need Printing?
read printYN
echo Does this machine need MySQL?
read dbYN
echo Will this machine be a Web Server?
read httpYN
echo Does this machine need DNS?
read dnsYN
echo Does this machine allow media files?
read mediaFilesYN

clear
unalias -a
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc
printTime "All alias have been removed."

clear
usermod -L root
printTime "Root account has been locked. Use 'usermod -U root' to unlock it."

clear
chmod 640 .bash_history
printTime "Bash history file permissions set."

clear
chmod 604 /etc/shadow
printTime "Read/Write permissions on shadow have been set."

clear
printTime "Check for any user folders that do not belong to any users in /home/."
ls -a /home/ >> ~/Desktop/Script.log

clear
printTime "Check for any files for users that should not be administrators in /etc/sudoers.d."
ls -a /etc/sudoers.d >> ~/Desktop/Script.log

clear
cp /etc/rc.local ~/Desktop/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
printTime "Any startup scripts have been removed."

clear
apt-get install ufw -y -qq
ufw enable
ufw deny 1337
printTime "Firewall enabled and port 1337 blocked."

clear
env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
printTime "Shellshock Bash vulnerability has been fixed."

clear
chmod 777 /etc/hosts
cp /etc/hosts ~/Desktop/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts
printTime "HOSTS file has been set to defaults."

clear
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf ~/Desktop/backups/
echo > /etc/lightdm/lightdm.conf
echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
chmod 644 /etc/lightdm/lightdm.conf
printTime "LightDM has been secured."

clear
find /bin/ -name "*.sh" -type f -delete
printTime "Scripts in bin have been removed."

clear
cp /etc/default/irqbalance ~/Desktop/backups/
echo > /etc/default/irqbalance
echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
printTime "IRQ Balance has been disabled."

clear
cp /etc/sysctl.conf ~/Desktop/backups/
echo > /etc/sysctl.conf
echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############" >> /etc/sysctl.conf
sysctl -p >> /dev/null
printTime "Sysctl has been configured."


echo Disable IPv6?
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	printTime "IPv6 has been disabled."
fi

clear
if [ $sambaYN == no ]
then
	ufw deny netbios-ns
	ufw deny netbios-dgm
	ufw deny netbios-ssn
	ufw deny microsoft-ds
	apt-get purge samba -y -qq
	apt-get purge samba-common -y  -qq
	apt-get purge samba-common-bin -y -qq
	apt-get purge samba4 -y -qq
	clear
	printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
elif [ $sambaYN == yes ]
then
	ufw allow netbios-ns
	ufw allow netbios-dgm
	ufw allow netbios-ssn
	ufw allow microsoft-ds
	apt-get install samba -y -qq
	apt-get install system-config-samba -y -qq
	cp /etc/samba/smb.conf ~/Desktop/backups/
	if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
	then
		sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
	fi
	sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf
	
	echo Type all user account names, with a space in between
	read -a usersSMB
	usersSMBLength=${#usersSMB[@]}	
	for (( i=0;i<$usersSMBLength;i++))
	do
		echo -e 'Moodle!22\nMoodle!22' | smbpasswd -a ${usersSMB[${i}]}
		printTime "${usersSMB[${i}]} has been given the password 'Moodle!22' for Samba."
	done
	printTime "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba config file has been configured."
	clear
else
	echo Response not recognized.
fi
printTime "Samba is complete."

clear
if [ $ftpYN == no ]
then
	ufw deny ftp 
	ufw deny sftp 
	ufw deny saft 
	ufw deny ftps-data 
	ufw deny ftps
	apt-get purge vsftpd -y -qq
	printTime "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	cp /etc/vsftpd/vsftpd.conf ~/Desktop/backups/
	cp /etc/vsftpd.conf ~/Desktop/backups/
	gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
	service vsftpd restart
	printTime "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
else
	echo Response not recognized.
fi
printTime "FTP is complete."


clear
if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge openssh-server -y -qq
	printTime "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y -qq
	ufw allow ssh
	cp /etc/ssh/sshd_config ~/Desktop/backups/	
	echo Type all user account names, with a space in between
	read usersSSH
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	sshd -t
	service ssh restart
	mkdir ~/.ssh
	chmod 700 ~/.ssh
	ssh-keygen -t rsa
	printTime "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
else
	echo Response not recognized.
fi
printTime "SSH is complete."

clear
if [ $telnetYN == no ]
then
	ufw deny telnet 
	ufw deny rtelnet 
	ufw deny telnets
	apt-get purge telnet -y -qq
	apt-get purge telnetd -y -qq
	apt-get purge inetutils-telnetd -y -qq
	apt-get purge telnetd-ssl -y -qq
	printTime "Telnet port has been denied on the firewall and Telnet has been removed."
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	printTime "Telnet port has been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Telnet is complete."



clear
if [ $mailYN == no ]
then
	ufw deny smtp 
	ufw deny pop2 
	ufw deny pop3
	ufw deny imap2 
	ufw deny imaps 
	ufw deny pop3s
	printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
elif [ $mailYN == yes ]
then
	ufw allow smtp 
	ufw allow pop2 
	ufw allow pop3
	ufw allow imap2 
	ufw allow imaps 
	ufw allow pop3s
	printTime "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Mail is complete."



clear
if [ $printYN == no ]
then
	ufw deny ipp 
	ufw deny printer 
	ufw deny cups
	printTime "ipp, printer, and cups ports have been denied on the firewall."
elif [ $printYN == yes ]
then
	ufw allow ipp 
	ufw allow printer 
	ufw allow cups
	printTime "ipp, printer, and cups ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "Printing is complete."



clear
if [ $dbYN == no ]
then
	ufw deny ms-sql-s 
	ufw deny ms-sql-m 
	ufw deny mysql 
	ufw deny mysql-proxy
	apt-get purge mysql -y -qq
	apt-get purge mysql-client-core-5.5 -y -qq
	apt-get purge mysql-client-core-5.6 -y -qq
	apt-get purge mysql-common-5.5 -y -qq
	apt-get purge mysql-common-5.6 -y -qq
	apt-get purge mysql-server -y -qq
	apt-get purge mysql-server-5.5 -y -qq
	apt-get purge mysql-server-5.6 -y -qq
	apt-get purge mysql-client-5.5 -y -qq
	apt-get purge mysql-client-5.6 -y -qq
	apt-get purge mysql-server-core-5.6 -y -qq
	printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	apt-get install mysql-server-5.6 -y -qq
	cp /etc/my.cnf ~/Desktop/backups/
	cp /etc/mysql/my.cnf ~/Desktop/backups/
	cp /usr/etc/my.cnf ~/Desktop/backups/
	cp ~/.my.cnf ~/Desktop/backups/
	if grep -q "bind-address" "/etc/mysql/my.cnf"
	then
		sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
	fi
	gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit ~/.my.cnf
	service mysql restart
	printTime "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
else
	echo Response not recognized.
fi
printTime "MySQL is complete."

apt-get install libpam-cracklib -y

echo "
EXPIRE=30
INACTIVE=30

" >> /etc/default/useradd

clear
if [ $httpYN == no ]
then
	ufw deny http
	ufw deny https
	apt-get purge apache2 -y -qq
	rm -r /var/www/*
	printTime "http and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
elif [ $httpYN == yes ]
then
	apt-get install apache2 -y -qq
	ufw allow http 
	ufw allow https
	cp /etc/apache2/apache2.conf ~/Desktop/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2

	printTime "http and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
else
	echo Response not recognized.
fi
printTime "Web Server is complete."



clear
if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get purge bind9 -qq
	printTime "domain port has been denied on the firewall. DNS name binding has been removed."
elif [ $dnsYN == yes ]
then
	ufw allow domain
	printTime "domain port has been allowed on the firewall."
else
	echo Response not recognized.
fi
printTime "DNS is complete."


clear
if [ $mediaFilesYN == no ]
then
	find / -name "*.midi" -type f >> ~/Desktop/Script.log
	find / -name "*.mid" -type f >> ~/Desktop/Script.log
	find / -name "*.mod" -type f >> ~/Desktop/Script.log
	find / -name "*.mp3" -type f >> ~/Desktop/Script.log
	find / -name "*.mp2" -type f >> ~/Desktop/Script.log
	find / -name "*.mpa" -type f >> ~/Desktop/Script.log
	find / -name "*.abs" -type f >> ~/Desktop/Script.log
	find / -name "*.mpega" -type f >> ~/Desktop/Script.log
	find / -name "*.au" -type f >> ~/Desktop/Script.log
	find / -name "*.snd" -type f >> ~/Desktop/Script.log
	find / -name "*.wav" -type f >> ~/Desktop/Script.log
	find / -name "*.aiff" -type f >> ~/Desktop/Script.log
	find / -name "*.aif" -type f >> ~/Desktop/Script.log
	find / -name "*.sid" -type f >> ~/Desktop/Script.log
	find / -name "*.flac" -type f >> ~/Desktop/Script.log
	find / -name "*.ogg" -type f >> ~/Desktop/Script.log
	clear
	printTime "All audio files has been listed."

	find / -name "*.mpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpg" -type f >> ~/Desktop/Script.log
	find / -name "*.mpe" -type f >> ~/Desktop/Script.log
	find / -name "*.dl" -type f >> ~/Desktop/Script.log
	find / -name "*.movie" -type f >> ~/Desktop/Script.log
	find / -name "*.movi" -type f >> ~/Desktop/Script.log
	find / -name "*.mv" -type f >> ~/Desktop/Script.log
	find / -name "*.iff" -type f >> ~/Desktop/Script.log
	find / -name "*.anim5" -type f >> ~/Desktop/Script.log
	find / -name "*.anim3" -type f >> ~/Desktop/Script.log
	find / -name "*.anim7" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.vfw" -type f >> ~/Desktop/Script.log
	find / -name "*.avx" -type f >> ~/Desktop/Script.log
	find / -name "*.fli" -type f >> ~/Desktop/Script.log
	find / -name "*.flc" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.qt" -type f >> ~/Desktop/Script.log
	find / -name "*.spl" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.dcr" -type f >> ~/Desktop/Script.log
	find / -name "*.dir" -type f >> ~/Desktop/Script.log
	find / -name "*.dxr" -type f >> ~/Desktop/Script.log
	find / -name "*.rpm" -type f >> ~/Desktop/Script.log
	find / -name "*.rm" -type f >> ~/Desktop/Script.log
	find / -name "*.smi" -type f >> ~/Desktop/Script.log
	find / -name "*.ra" -type f >> ~/Desktop/Script.log
	find / -name "*.ram" -type f >> ~/Desktop/Script.log
	find / -name "*.rv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.asf" -type f >> ~/Desktop/Script.log
	find / -name "*.asx" -type f >> ~/Desktop/Script.log
	find / -name "*.wma" -type f >> ~/Desktop/Script.log
	find / -name "*.wax" -type f >> ~/Desktop/Script.log
	find / -name "*.wmv" -type f >> ~/Desktop/Script.log
	find / -name "*.wmx" -type f >> ~/Desktop/Script.log
	find / -name "*.3gp" -type f >> ~/Desktop/Script.log
	find / -name "*.mov" -type f >> ~/Desktop/Script.log
	find / -name "*.mp4" -type f >> ~/Desktop/Script.log
	find / -name "*.avi" -type f >> ~/Desktop/Script.log
	find / -name "*.swf" -type f >> ~/Desktop/Script.log
	find / -name "*.flv" -type f >> ~/Desktop/Script.log
	find / -name "*.m4v" -type f >> ~/Desktop/Script.log
	clear
	printTime "All video files have been listed."
	
	find / -name "*.tiff" -type f >> ~/Desktop/Script.log
	find / -name "*.tif" -type f >> ~/Desktop/Script.log
	find / -name "*.rs" -type f >> ~/Desktop/Script.log
	find / -name "*.im1" -type f >> ~/Desktop/Script.log
	find / -name "*.gif" -type f >> ~/Desktop/Script.log
	find / -name "*.jpeg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpg" -type f >> ~/Desktop/Script.log
	find / -name "*.jpe" -type f >> ~/Desktop/Script.log
	find / -name "*.png" -type f >> ~/Desktop/Script.log
	find / -name "*.rgb" -type f >> ~/Desktop/Script.log
	find / -name "*.xwd" -type f >> ~/Desktop/Script.log
	find / -name "*.xpm" -type f >> ~/Desktop/Script.log
	find / -name "*.ppm" -type f >> ~/Desktop/Script.log
	find / -name "*.pbm" -type f >> ~/Desktop/Script.log
	find / -name "*.pgm" -type f >> ~/Desktop/Script.log
	find / -name "*.pcx" -type f >> ~/Desktop/Script.log
	find / -name "*.ico" -type f >> ~/Desktop/Script.log
	find / -name "*.svg" -type f >> ~/Desktop/Script.log
	find / -name "*.svgz" -type f >> ~/Desktop/Script.log
	clear
	printTime "All image files have been listed."
else
	echo Response not recognized.
fi
printTime "Media files are complete."

clear
find / -type f -perm 777 >> ~/Desktop/Script.log
find / -type f -perm 776 >> ~/Desktop/Script.log
find / -type f -perm 775 >> ~/Desktop/Script.log
find / -type f -perm 774 >> ~/Desktop/Script.log
find / -type f -perm 773 >> ~/Desktop/Script.log
find / -type f -perm 772 >> ~/Desktop/Script.log
find / -type f -perm 771 >> ~/Desktop/Script.log
find / -type f -perm 770 >> ~/Desktop/Script.log
find / -type f -perm 767 >> ~/Desktop/Script.log
find / -type f -perm 766 >> ~/Desktop/Script.log
find / -type f -perm 765 >> ~/Desktop/Script.log
find / -type f -perm 764 >> ~/Desktop/Script.log
find / -type f -perm 763 >> ~/Desktop/Script.log
find / -type f -perm 762 >> ~/Desktop/Script.log
find / -type f -perm 761 >> ~/Desktop/Script.log
find / -type f -perm 760 >> ~/Desktop/Script.log
find / -type f -perm 757 >> ~/Desktop/Script.log
find / -type f -perm 756 >> ~/Desktop/Script.log
find / -type f -perm 755 >> ~/Desktop/Script.log
find / -type f -perm 754 >> ~/Desktop/Script.log
find / -type f -perm 753 >> ~/Desktop/Script.log
find / -type f -perm 752 >> ~/Desktop/Script.log
find / -type f -perm 751 >> ~/Desktop/Script.log
find / -type f -perm 750 >> ~/Desktop/Script.log
find / -type f -perm 747 >> ~/Desktop/Script.log
find / -type f -perm 746 >> ~/Desktop/Script.log
find / -type f -perm 745 >> ~/Desktop/Script.log
find / -type f -perm 744 >> ~/Desktop/Script.log
find / -type f -perm 743 >> ~/Desktop/Script.log
find / -type f -perm 742 >> ~/Desktop/Script.log
find / -type f -perm 741 >> ~/Desktop/Script.log
find / -type f -perm 740 >> ~/Desktop/Script.log
find / -type f -perm 737 >> ~/Desktop/Script.log
find / -type f -perm 736 >> ~/Desktop/Script.log
find / -type f -perm 735 >> ~/Desktop/Script.log
find / -type f -perm 734 >> ~/Desktop/Script.log
find / -type f -perm 733 >> ~/Desktop/Script.log
find / -type f -perm 732 >> ~/Desktop/Script.log
find / -type f -perm 731 >> ~/Desktop/Script.log
find / -type f -perm 730 >> ~/Desktop/Script.log
find / -type f -perm 727 >> ~/Desktop/Script.log
find / -type f -perm 726 >> ~/Desktop/Script.log
find / -type f -perm 725 >> ~/Desktop/Script.log
find / -type f -perm 724 >> ~/Desktop/Script.log
find / -type f -perm 723 >> ~/Desktop/Script.log
find / -type f -perm 722 >> ~/Desktop/Script.log
find / -type f -perm 721 >> ~/Desktop/Script.log
find / -type f -perm 720 >> ~/Desktop/Script.log
find / -type f -perm 717 >> ~/Desktop/Script.log
find / -type f -perm 716 >> ~/Desktop/Script.log
find / -type f -perm 715 >> ~/Desktop/Script.log
find / -type f -perm 714 >> ~/Desktop/Script.log
find / -type f -perm 713 >> ~/Desktop/Script.log
find / -type f -perm 712 >> ~/Desktop/Script.log
find / -type f -perm 711 >> ~/Desktop/Script.log
find / -type f -perm 710 >> ~/Desktop/Script.log
find / -type f -perm 707 >> ~/Desktop/Script.log
find / -type f -perm 706 >> ~/Desktop/Script.log
find / -type f -perm 705 >> ~/Desktop/Script.log
find / -type f -perm 704 >> ~/Desktop/Script.log
find / -type f -perm 703 >> ~/Desktop/Script.log
find / -type f -perm 702 >> ~/Desktop/Script.log
find / -type f -perm 701 >> ~/Desktop/Script.log
find / -type f -perm 700 >> ~/Desktop/Script.log
printTime "All files with file permissions between 700 and 777 have been listed above."

clear
find / -name "*.php" -type f >> ~/Desktop/Script.log
printTime "All PHP files have been listed above. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

echo '
#Reference File
# Package generated configuration file
# See the sshd_config(5) manpage for details

AllowTcpForwarding yes
ClientAliveCountMax 2
Compression no
MaxSessions 2
AllowAgentForwarding no

# What ports, IPs and protocols we listen for
Port 22000
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation sandbox

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile %h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
#PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
MaxAuthTries 2

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes
' >> /etc/ssh/ssh_config

clear
apt-get purge netcat -y -qq
apt-get purge netcat-openbsd -y -qq
apt-get purge netcat-traditional -y -qq
apt-get purge ncat -y -qq
apt-get purge pnetcat -y -qq
apt-get purge socat -y -qq
apt-get purge sock -y -qq
apt-get purge socket -y -qq
apt-get purge sbd -y -qq
rm /usr/bin/nc
clear
printTime "Netcat and all other instances have been removed."

apt-get purge john -y -qq
apt-get purge john-data -y -qq
clear
printTime "John the Ripper has been removed."

apt-get purge hydra -y -qq
apt-get purge hydra-gtk -y -qq
clear
printTime "Hydra has been removed."

apt-get purge aircrack-ng -y -qq
clear
printTime "Aircrack-NG has been removed."

apt-get purge fcrackzip -y -qq
clear
printTime "FCrackZIP has been removed."

apt-get purge lcrack -y -qq
clear
printTime "LCrack has been removed."

apt-get purge ophcrack -y -qq
apt-get purge ophcrack-cli -y -qq
clear
printTime "OphCrack has been removed."

apt-get purge pdfcrack -y -qq
clear
printTime "PDFCrack has been removed."

apt-get purge pyrit -y -qq
clear
printTime "Pyrit has been removed."

apt-get purge rarcrack -y -qq
clear
printTime "RARCrack has been removed."

apt-get purge sipcrack -y -qq
clear
printTime "SipCrack has been removed."

apt-get purge irpas -y -qq
clear
printTime "IRPAS has been removed."

clear
printTime 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

apt-get purge logkeys -y -qq
clear 
printTime "LogKeys has been removed."

apt-get purge zeitgeist-core -y -qq
apt-get purge zeitgeist-datahub -y -qq
apt-get purge python-zeitgeist -y -qq
apt-get purge rhythmbox-plugin-zeitgeist -y -qq
apt-get purge zeitgeist -y -qq
printTime "Zeitgeist has been removed."

apt-get purge nfs-kernel-server -y -qq
apt-get purge nfs-common -y -qq
apt-get purge portmap -y -qq
apt-get purge rpcbind -y -qq
apt-get purge autofs -y -qq
printTime "NFS has been removed."

apt-get purge nginx -y -qq
apt-get purge nginx-common -y -qq
printTime "NGINX has been removed."

apt-get purge inetd -y -qq
apt-get purge openbsd-inetd -y -qq
apt-get purge xinetd -y -qq
apt-get purge inetutils-ftp -y -qq
apt-get purge inetutils-ftpd -y -qq
apt-get purge inetutils-inetd -y -qq
apt-get purge inetutils-ping -y -qq
apt-get purge inetutils-syslogd -y -qq
apt-get purge inetutils-talk -y -qq
apt-get purge inetutils-talkd -y -qq
apt-get purge inetutils-telnet -y -qq
apt-get purge inetutils-telnetd -y -qq
apt-get purge inetutils-tools -y -qq
apt-get purge inetutils-traceroute -y -qq
printTime "Inetd (super-server) and all inet utilities have been removed."

clear
apt-get purge vnc4server -y -qq
apt-get purge vncsnapshot -y -qq
apt-get purge vtgrab -y -qq
printTime "VNC has been removed."

clear
apt-get purge snmp -y -qq
printTime "SNMP has been removed."

clear
cp /etc/login.defs ~/Desktop/backups/
sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i '162s/.*/PASS_MIN_LEN\o0118/' /etc/login.defs
sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
printTime "Password policies have been set with /etc/login.defs."

clear
apt-get install libpam-cracklib -y -qq
cp /etc/pam.d/common-auth ~/Desktop/backups/
cp /etc/pam.d/common-password ~/Desktop/backups/
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
printTime "If password policies are not correctly configured, try this for /etc/pam.d/common-password:\npassword requisite pam_cracklib.so retry=3 minlen=10 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
printTime "Password policies have been set with and /etc/pam.d."

clear
apt-get install iptables -y -qq
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
printTime "All outside packets from internet claiming to be from loopback are denied."

clear
cp /etc/init/control-alt-delete.conf ~/Desktop/backups/
sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
printTime "Reboot using Ctrl-Alt-Delete has been disabled."

clear
apt-get install apparmor apparmor-profiles -y -qq
printTime "AppArmor has been installed."

clear
crontab -l > ~/Desktop/backups/crontab-old
crontab -r
printTime "Crontab has been backed up. All startup tasks have been removed from crontab."

clear
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
cd ..
printTime "Only root allowed in cron."

clear
chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
printTime "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

clear
if [[ $(lsb_release -r) == "Release:	14.04" ]] || [[ $(lsb_release -r) == "Release:	14.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ trusty-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	12.04" ]] || [[ $(lsb_release -r) == "Release:	12.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list ~/Desktop/backups/
	echo -e "deb http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb-src http://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
else
	echo “Error, cannot detect OS version”
fi
printTime "Apt Repositories have been added."

clear
apt-get update -qq
apt-get upgrade -qq
apt-get dist-upgrade -qq
printTime "Ubuntu OS has checked for updates and has been upgraded."

clear
apt-get autoremove -y -qq
apt-get autoclean -y -qq
apt-get clean -y -qq
printTime "All unused packages have been removed."

clear
echo "Check to verify that all update settings are correct."
update-manager

clear
apt-get update
apt-get upgrade openssl libssl-dev
apt-cache policy openssl libssl-dev
printTime "OpenSSL heart bleed bug has been fixed."

clear
if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]
then
	grep root /etc/passwd | wc -l
	echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
	read waiting
else
	printTime "UID 0 is correctly set to root."
fi

clear
mkdir -p ~/Desktop/logs
chmod 777 ~/Desktop/logs
printTime "Logs folder has been created on the Desktop."

clear
touch ~/Desktop/logs/allusers.txt
uidMin=$(grep "^UID_MIN" /etc/login.defs)
uidMax=$(grep "^UID_MAX" /etc/login.defs)
echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
printTime "All users have been logged."
cp /etc/services ~/Desktop/logs/allports.log
printTime "All ports log has been created."
dpkg -l > ~/Desktop/logs/packages.log
printTime "All packages log has been created."
apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
printTime "All manually instealled packages log has been created."
service --status-all > ~/Desktop/logs/allservices.txt
printTime "All running services log has been created."
ps ax > ~/Desktop/logs/processes.log
printTime "All running processes log has been created."
ss -l > ~/Desktop/logs/socketconnections.log
printTime "All socket connections log has been created."
sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
printTime "All listening ports log has been created."
cp /var/log/auth.log ~/Desktop/logs/auth.log
printTime "Auth log has been created."
cp /var/log/syslog ~/Desktop/logs/syslog.log
printTime "System log has been created."

clear
apt-get install tree -y -qq
apt-get install diffuse -y -qq
mkdir Desktop/Comparatives
chmod 777 Desktop/Comparatives

cp /etc/apt/apt.conf.d/10periodic Desktop/Comparatives/
cp Desktop/logs/allports.log Desktop/Comparatives/
cp Desktop/logs/allservices.txt Desktop/Comparatives/
touch Desktop/Comparatives/alltextfiles.txt
find . -type f -exec grep -Iq . {} \; -and -print >> Desktop/Comparatives/alltextfiles.txt
cp Desktop/logs/allusers.txt Desktop/Comparatives/
cp /etc/apache2/apache2.conf Desktop/Comparatives/
cp /etc/pam.d/common-auth Desktop/Comparatives/
cp /etc/pam.d/common-password Desktop/Comparatives/
cp /etc/init/control-alt-delete.conf Desktop/Comparatives/
crontab -l > Desktop/Comparatives/crontab.log
cp /etc/group Desktop/Comparatives/
cp /etc/hosts Desktop/Comparatives/
touch Desktop/Comparatives/initctl-running.txt
initctl list | grep running > Desktop/Comparatives/initctl-running.txt
cp /etc/lightdm/lightdm.conf Desktop/Comparatives/
cp Desktop/logs/listeningports.log Desktop/Comparatives/
cp /etc/login.defs Desktop/Comparatives/
cp Desktop/logs/manuallyinstalled.log Desktop/Comparatives/
cp /etc/mysql/my.cnf Desktop/Comparatives/
cp Desktop/logs/packages.log Desktop/Comparatives/
cp /etc/passwd Desktop/Comparatives/
cp Desktop/logs/processes.log Desktop/Comparatives/
cp /etc/rc.local Desktop/Comparatives/
cp /etc/samba/smb.conf Desktop/Comparatives/
cp Desktop/logs/socketconnections.log Desktop/Comparatives/
cp /etc/apt/sources.list Desktop/Comparatives/
cp /etc/ssh/sshd_config Desktop/Comparatives/
cp /etc/sudoers Desktop/Comparatives/
cp /etc/sysctl.conf Desktop/Comparatives/
tree / -o Desktop/Comparatives/tree.txt -n -p -h -u -g -D -v
cp /etc/vsftpd.conf Desktop/Comparatives/
printTime "Tree and Diffuse have been installed, files on current system have been copied for comparison."

chmod 777 -R Desktop/Comparatives/
chmod 777 -R Desktop/backups
chmod 777 -R Desktop/logs

clear

sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 2/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs

echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
apt-get install libpam-cracklib
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=10/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

apt-get install auditd && auditctl -e 

echo printing weird admins
mawk -F: '$1 == "sudo"' /etc/group

echo printing weird users
mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd

echo empty passwd
mawk -F: '$2 == ""' /etc/passwd

echo changing root passwd
passwd root

echo non-root uid 0 users
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd

echo removing all samba related pkgs
apt-get remove .*samba.* .*smb.*

echo more media stuff
find / -type f \( -name "*.mp3" -o -name "*.mp4" \)

echo more illegal tools
find /home -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \)

apt install bum -y

apt purge nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack -y && apt autoremove -y




echo world writable files
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print

echo no-user files 
find / -xdev \( -nouser -o -nogroup \) -print

echo disabling usbs
echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf
echo "disabling thunderbolt and firewire"
echo "blacklist firewire-core" >> /etc/modprobe.d/firewire.conf
echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf


apt install fail2ban -y
systemctl enable --now fail2ban

sudo apt-get install chkrootkit rkhunter
sudo chkrootkit -l
sudo rkhunter --update
sudo rkhunter --check
rkhunter -c --enable all --disable none

passwd -l root
apt install libpam-pwquality
pam-auth-update

touch /usr/share/pam-configs/faillock_notify
echo "
Name: Notify on failed login attempts
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
" >> /usr/share/pam-configs/faillock_notify
pam-auth-update


touch /usr/share/pam-configs/faillock
echo "
Name: Enforce on failed login attempt counter
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die] pam_faillock.so authfail
	sufficient pam_faillock.so authsucc
" >> /usr/share/pam-configs/faillock
pam-auth-update


echo allow-guest=false >> /etc/lightdm/lighdm.conf
echo greeter-hide-users=true >> /etc/lightdm/lighdm.conf
echo greeter-show-manual-login=true >> /etc/lightdm/lighdm.conf
echo autologin-user=none >> /etc/lightdm/lighdm.conf

echo EXPIRE=30 >> /etc/default/useradd
echo INACTIVE=30 >> /etc/dafauo 
echo "nospoof on" >> /etc/host.conft/useradd

apt install unattended-upgrades -y
dpkg-reconfigure unattended-upgrades


echo APT::Periodic::Update-Package-Lists "1"; >> /etc/apt/apt.conf.d/20auto-upgrades
echo APT::Periodic::Download-Upgradeable-Packages "1"; >> /etc/apt/apt.conf.d/20auto-upgrades
echo APT::Periodic::AutocleanInterval "7"; >> /etc/apt/apt.conf.d/20auto-upgrades
echo APT::Periodic::Unattended-Upgrade "1"; >> /etc/apt/apt.conf.d/20auto-upgrades

echo "
Unattended-Upgrade::Allowed-Origins {
	"${distro_id} stable";
		"${distro_id} ${distro_codename}-security";
			"${distro_id} ${distro_codename}-updates";
		};

		Unattended-Upgrade::Package-Blacklist {
			"libproxy1v5";		# since the school filter blocks the word proxy
		};

" >> /etc/apt/apt.conf/50auto-upgrades

apt install deborphan -y
deborphan --guess-all
deborphan --guess-data | xargs sudo apt-get -y remove --purge
deborphan | xargs sudo apt-get -y remove --purge



apt purge john nmap vuze frostwire kismet freeciv minetest minetest-server medusa hydra truecrack ophcrack nikto cryptcat nc netcat tightvncserver x11vnc nfs xinetd telnet rlogind rshd rcmd rexecd rbootd rquotad rstatd rusersd rwalld rexd fingerd tftpd telnet snmp netcat aisleriot nc -y && apt autoremove -y

echo "

Protocol 2
LogLevel VERBOSE
X11Forwarding no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no



" >> /etc/ssh/sshd_config

echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox
echo block pop ups in firefox


echo "
ServerSignature Off
ServerTokens Prod

" >> /etc/apache2/apache2.conf

echo "

fs.file-max = 65535
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.exec-shield = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 9

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Incase IPv6 is necessary
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1


" >> /etc/sysctl.conf
sysctl -p

apt install clamav chkrootkit rkhunter -y

freshclam 

apt install git -y
git clone https://github.com/CISOfy/lynis
cd lynis && ./lynis audit system | grep -E 'warning|suggestion' | sed -e 's/warning\[\]\=//g' | sed -e 's/suggestion\[\]\=//g'

apt install auditd -y
auditctl -e 1

sed -i 's/^TimedLoginEnable/#&/' /etc/gdm3/custom.conf
sed -i 's/^TimedLogin/#&/' /etc/gdm3/custom.conf
sed -i 's/^TimedLogindelay/#&/' /etc/gdm3/custom.conf
sed -i 's/^AutomaticLoginEnable/#&/' /etc/gdm3/custom.conf
sed -i 's/^AutomaticLogin/#&/' /etc/gdm3/custom.conf

apt update -y && apt dist-upgrade -y && apt autoremove -y 

echo preventing ip spoofing
grep -qF 'multi on' && sed 's/multi/nospoof/' || echo 'nospoof on' >> /etc/host.conf

curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

apt-get remove .*samba.* .*smb.* -y
apt install pamtester

printTime "Script is complete. Print logs?"
logp() {
	echo "pipe logs to less?"
            read Response
            case "$Response" in
                 yes|y)
			 cat ~/Desktop/Script.log | less
                     ;;
                 no|n)
			 exit 1
                     ;;
                 *) 
                     echo "respose: yes/no"
                     return 1
                     ;;
            esac
            }
until logp ; do : ; done



