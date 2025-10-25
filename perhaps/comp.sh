#!/bin/bash

# =============================================
# COMPREHENSIVE CYBERPATRIOT HARDENING SCRIPT
# For Ubuntu 20.04+ and Linux Mint 20+
# =============================================

set -euo pipefail
clear

# =============================================
# INITIALIZATION & LOGGING
# =============================================

# Script meta
SCRIPT_NAME="CyberPatriot_Ultimate_Hardening"
SCRIPT_VERSION="3.0"
startTime=$(date +"%s")

# Directories
BACKUP_DIR="$HOME/Desktop/backups"
LOG_DIR="$HOME/Desktop/logs"
COMP_DIR="$HOME/Desktop/Comparatives"

# Create directories
mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"
chmod 700 "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"

# Main log file
touch "$HOME/Desktop/Script.log"
echo "=== CyberPatriot Hardening Script Started $(date) ===" > "$HOME/Desktop/Script.log"
chmod 600 "$HOME/Desktop/Script.log"

printTime() {
    endTime=$(date +"%s")
    diffTime=$(($endTime-$startTime))
    if [ $(($diffTime / 60)) -lt 10 ]; then
        if [ $(($diffTime % 60)) -lt 10 ]; then
            echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> "$HOME/Desktop/Script.log"
        else
            echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> "$HOME/Desktop/Script.log"
        fi
    else
        if [ $(($diffTime % 60)) -lt 10 ]; then
            echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> "$HOME/Desktop/Script.log"
        else
            echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> "$HOME/Desktop/Script.log"
        fi
    fi
    echo "$1"
}

# =============================================
# INITIAL SYSTEM CHECKS
# =============================================

printTime "=== INITIAL SYSTEM CHECKS ==="

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
printTime "Script is being run as root."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    OS=$(lsb_release -i | cut -f2)
    VER=$(lsb_release -r | cut -f2)
fi
printTime "Detected OS: $OS $VER"

# Initial system information gathering
printTime "Gathering initial system information..."
echo '=== APT SOURCES ===' >> "$HOME/Desktop/Script.log"
grep -h "^deb" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null >> "$HOME/Desktop/Script.log" || true
echo '=== SUDOERS CONFIG ===' >> "$HOME/Desktop/Script.log"
grep -v "^#" /etc/sudoers | grep -v "^$" >> "$HOME/Desktop/Script.log" || true

# =============================================
# BACKUP CRITICAL FILES
# =============================================

printTime "=== BACKING UP CRITICAL FILES ==="

backup_files=(
    "/etc/passwd"
    "/etc/group"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/sysctl.conf"
    "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password"
    "/etc/login.defs"
    "/etc/hosts"
    "/etc/lightdm/lightdm.conf"
    "/etc/apache2/apache2.conf"
    "/etc/mysql/my.cnf"
    "/etc/samba/smb.conf"
    "/etc/vsftpd.conf"
    "/etc/rc.local"
)

for file in "${backup_files[@]}"; do
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/" 2>/dev/null && printTime "Backed up $file" || true
    fi
done

# =============================================
# PACKAGE MANAGEMENT & SYSTEM UPDATE
# =============================================

printTime "=== PACKAGE MANAGEMENT ==="

# Update package lists
apt-get update -y

# Full system upgrade
apt-get dist-upgrade -y
apt-get install -f -y
apt-get autoremove -y --purge
apt-get autoclean -y
apt-get check

# Configure automatic updates
cat > /etc/apt/apt.conf.d/10periodic << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
printTime "Automatic updates configured"

# Remove high-risk packages
printTime "Removing dangerous packages..."
high_risk_packages=(
    "john" "john-data" "hydra" "hydra-gtk" "aircrack-ng" "ophcrack" "ophcrack-cli"
    "fcrackzip" "lcrack" "pdfcrack" "pyrit" "rarcrack" "sipcrack" "irpas"
    "logkeys" "nmap" "zenmap" "wireshark" "netcat" "netcat-openbsd" "netcat-traditional"
    "ncat" "pnetcat" "socat" "sock" "socket" "sbd" "nessus" "metasploit-framework"
    "freeciv" "minetest" "minetest-server" "medusa" "truecrack" "cryptcat"
    "tightvncserver" "x11vnc" "nfs-kernel-server" "nfs-common" "portmap" "rpcbind"
    "autofs" "nginx" "nginx-common" "inetd" "openbsd-inetd" "xinetd"
    "inetutils-ftp" "inetutils-ftpd" "inetutils-inetd" "inetutils-ping"
    "inetutils-syslogd" "inetutils-talk" "inetutils-talkd" "inetutils-telnet"
    "inetutils-telnetd" "inetutils-tools" "inetutils-traceroute"
    "vnc4server" "vncsnapshot" "vtgrab" "snmp" "zeigeist-core" "zeigeist-datahub"
    "python-zeitgeist" "rhythmbox-plugin-zeitgeist" "zeitgeist"
)

for pkg in "${high_risk_packages[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg "; then
        apt-get purge -y "$pkg" && printTime "Removed: $pkg" || true
    fi
done

# Remove games
apt-get purge -y aisleriot gnome-mahjongg gnome-mines gnome-sudoku

# =============================================
# USER ACCOUNT MANAGEMENT
# =============================================

printTime "=== USER ACCOUNT MANAGEMENT ==="

# Interactive user management
echo "Type existing user account names to manage (space separated):"
read -a users

for user in "${users[@]}"; do
    if id "$user" &>/dev/null; then
        echo "Delete user $user? (yes/no)"
        read del_yn
        if [ "$del_yn" = "yes" ]; then
            userdel -r "$user" && printTime "Deleted user: $user"
        else
            echo "Make $user administrator? (yes/no)"
            read admin_yn
            if [ "$admin_yn" = "yes" ]; then
                usermod -aG sudo,adm,lpadmin,sambashare "$user"
                printTime "Made $user administrator"
            else
                gpasswd -d "$user" sudo
                gpasswd -d "$user" adm
                gpasswd -d "$user" lpadmin
                gpasswd -d "$user" sambashare
                gpasswd -d "$user" root
                printTime "Made $user standard user"
            fi
            
            echo "Set custom password for $user? (yes/no)"
            read pass_yn
            if [ "$pass_yn" = "yes" ]; then
                echo "Enter new password for $user:"
                read -s user_pass
                echo -e "$user_pass\n$user_pass" | passwd "$user"
                printTime "Set custom password for $user"
            else
                echo -e "CyberPatriot2024!\nCyberPatriot2024!" | passwd "$user"
                printTime "Set default password for $user"
            fi
            
            # Password policies
            passwd -x30 -n3 -w7 "$user"
            usermod -L "$user"  # Lock account temporarily
            printTime "Applied password policies to $user"
        fi
    else
        printTime "User $user not found"
    fi
done

# Create new users
echo "Create new users? (yes/no)"
read create_new
if [ "$create_new" = "yes" ]; then
    echo "Type new user account names (space separated):"
    read -a new_users
    
    for new_user in "${new_users[@]}"; do
        adduser --gecos "" --disabled-password "$new_user"
        echo -e "CyberPatriot2024!\nCyberPatriot2024!" | passwd "$new_user"
        passwd -x30 -n3 -w7 "$new_user"
        usermod -L "$new_user"
        printTime "Created and secured user: $new_user"
    done
fi

# =============================================
# SERVICE CONFIGURATION
# =============================================

printTime "=== SERVICE CONFIGURATION ==="

# Interactive service configuration
echo "Does this machine need Samba? (yes/no)"
read sambaYN
echo "Does this machine need FTP? (yes/no)"
read ftpYN
echo "Does this machine need SSH? (yes/no)"
read sshYN
echo "Does this machine need Telnet? (yes/no)"
read telnetYN
echo "Does this machine need Mail? (yes/no)"
read mailYN
echo "Does this machine need Printing? (yes/no)"
read printYN
echo "Does this machine need MySQL? (yes/no)"
read dbYN
echo "Will this machine be a Web Server? (yes/no)"
read httpYN
echo "Does this machine need DNS? (yes/no)"
read dnsYN
echo "Does this machine allow media files? (yes/no)"
read mediaFilesYN

# SSH Configuration
if [ "$sshYN" = "no" ]; then
    ufw deny ssh
    apt-get purge openssh-server -y
    printTime "SSH removed"
else
    apt-get install openssh-server -y
    ufw allow ssh
    
    # Advanced SSH hardening
    backup_file "/etc/ssh/sshd_config"
    cat > /etc/ssh/sshd_config << 'EOF'
# CyberPatriot SSH Configuration
Protocol 2
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Security settings
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Cryptography
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Network restrictions
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# PAM
UsePAM yes

# User restrictions
AllowUsers
EOF

    # Add allowed users if specified
    if [ ${#users[@]} -gt 0 ]; then
        sed -i "s/^AllowUsers/AllowUsers ${users[*]}/" /etc/ssh/sshd_config
    fi
    
    sshd -t && systemctl restart ssh
    printTime "SSH hardened and restarted"
fi

# Web Server Configuration
if [ "$httpYN" = "no" ]; then
    ufw deny http
    ufw deny https
    apt-get purge apache2 nginx -y
    printTime "Web servers removed"
else
    apt-get install apache2 -y
    ufw allow http
    ufw allow https
    
    # Secure Apache
    backup_file "/etc/apache2/apache2.conf"
    echo -e "\n<Directory />\nAllowOverride None\nOrder Deny,Allow\nDeny from all\n</Directory>" >> /etc/apache2/apache2.conf
    echo "ServerTokens Prod" >> /etc/apache2/apache2.conf
    echo "ServerSignature Off" >> /etc/apache2/apache2.conf
    systemctl restart apache2
    printTime "Apache secured"
fi

# MySQL Configuration
if [ "$dbYN" = "no" ]; then
    ufw deny mysql
    apt-get purge mysql-server -y
    printTime "MySQL removed"
else
    apt-get install mysql-server -y
    ufw allow mysql
    
    # Secure MySQL
    backup_file "/etc/mysql/my.cnf"
    echo "bind-address = 127.0.0.1" >> /etc/mysql/my.cnf
    mysql_secure_installation << EOF
n
y
y
y
y
EOF
    printTime "MySQL secured"
fi

# =============================================
# SECURITY HARDENING
# =============================================

printTime "=== SECURITY HARDENING ==="

# File permissions
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/apt/sources.list
chmod 700 /home/*

# Secure sudoers
echo "Defaults authenticate" >> /etc/sudoers
echo "Defaults use_pty" >> /etc/sudoers
echo "Defaults timestamp_timeout=5" >> /etc/sudoers

# Configure UFW
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw deny 1337

# Advanced iptables rules
apt-get install iptables-persistent -y
iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow specific services based on configuration
[ "$sshYN" = "yes" ] && iptables -A INPUT -p tcp --dport 22 -j ACCEPT
[ "$httpYN" = "yes" ] && iptables -A INPUT -p tcp --dport 80 -j ACCEPT
[ "$httpYN" = "yes" ] && iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4

# Sysctl hardening
backup_file "/etc/sysctl.conf"
cat >> /etc/sysctl.conf << 'EOF'
# Network security
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1

# Kernel security
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

sysctl -p

# PAM configuration
apt-get install libpam-cracklib -y
backup_file "/etc/pam.d/common-password"
cat > /etc/pam.d/common-password << 'EOF'
# CyberPatriot PAM Configuration
password requisite pam_cracklib.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password requisite pam_pwhistory.so use_authtok remember=5
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
password requisite pam_deny.so
password required pam_permit.so
EOF

# Login definitions
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# =============================================
# FILE SYSTEM SECURITY
# =============================================

printTime "=== FILE SYSTEM SECURITY ==="

# Remove media files if not allowed
if [ "$mediaFilesYN" = "no" ]; then
    printTime "Removing media files..."
    
    # Audio files
    find /home -type f \( -name "*.mp3" -o -name "*.wav" -o -name "*.flac" -o -name "*.m4a" -o -name "*.ogg" \) -delete
    
    # Video files
    find /home -type f \( -name "*.mp4" -o -name "*.avi" -o -name "*.mov" -o -name "*.mkv" -o -name "*.flv" \) -delete
    
    # Image files
    find /home -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.bmp" \) -delete
    
    printTime "Media files removed from home directories"
fi

# Find suspicious files
printTime "Searching for suspicious files..."
find / -type f -perm /6000 > "$LOG_DIR/suid_sgid_files.log" 2>/dev/null
find / -type f -perm /o+w > "$LOG_DIR/world_writable_files.log" 2>/dev/null
find / -nouser -o -nogroup > "$LOG_DIR/no_owner_files.log" 2>/dev/null
find / -name "*.php" -type f > "$LOG_DIR/php_files.log" 2>/dev/null

# Remove dangerous files
find /bin/ -name "*.sh" -type f -delete 2>/dev/null || true

# Secure critical directories
chmod 700 /root
chmod 600 /root/.bash_history
chmod 600 /home/*/.bash_history 2>/dev/null || true

# =============================================
# SECURITY TOOLS & MONITORING
# =============================================

printTime "=== SECURITY TOOLS ==="

# Install security tools
apt-get install -y \
    chkrootkit \
    rkhunter \
    clamav \
    fail2ban \
    auditd \
    unattended-upgrades \
    libpam-pwquality

# Update ClamAV
freshclam

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Configure auditd
systemctl enable auditd
systemctl start auditd

# Run security scans
printTime "Running security scans..."
rkhunter --update
rkhunter --check --sk --rwo >> "$HOME/Desktop/Script.log"
chkrootkit >> "$HOME/Desktop/Script.log"

# =============================================
# FORENSIC DATA COLLECTION
# =============================================

printTime "=== FORENSIC DATA COLLECTION ==="

# System information
uname -a > "$COMP_DIR/system_info.txt"
cat /etc/os-release >> "$COMP_DIR/system_info.txt"

# User information
getent passwd > "$COMP_DIR/all_users.txt"
getent group > "$COMP_DIR/all_groups.txt"
lastlog > "$COMP_DIR/last_logins.txt"

# Process information
ps aux > "$COMP_DIR/processes.txt"
systemctl list-unit-files --type=service > "$COMP_DIR/services.txt"

# Network information
ss -tuln > "$COMP_DIR/listening_ports.txt"
netstat -tuln > "$COMP_DIR/network_connections.txt"

# Package information
dpkg -l > "$COMP_DIR/installed_packages.txt"
apt-mark showmanual > "$COMP_DIR/manual_packages.txt"

# File system information
find / -type f -perm /777 > "$COMP_DIR/world_writable_files.txt" 2>/dev/null
find / -name ".*" -type f > "$COMP_DIR/hidden_files.txt" 2>/dev/null

# Security configuration
ufw status verbose > "$COMP_DIR/ufw_status.txt"
cat /etc/ssh/sshd_config > "$COMP_DIR/ssh_config.txt"

# =============================================
# COMPETITION-SPECIFIC ENHANCEMENTS
# =============================================

printTime "=== COMPETITION ENHANCEMENTS ==="

# Disable unnecessary hardware
echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf
echo 'install firewire-core /bin/true' >> /etc/modprobe.d/firewire.conf
echo 'install thunderbolt /bin/true' >> /etc/modprobe.d/thunderbolt.conf

# Secure GRUB
chmod 600 /boot/grub/grub.cfg
echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root grub.pbkdf2.sha512.10000." >> /etc/grub.d/40_custom
update-grub

# Configure login banners
echo "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue
echo "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue.net

# Secure cron
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
chmod 600 /etc/crontab
chmod 600 /etc/cron.*/*

# Remove startup scripts
echo 'exit 0' > /etc/rc.local

# =============================================
# FINAL CHECKS & CLEANUP
# =============================================

printTime "=== FINAL CHECKS ==="

# Check for hidden UID 0 users
hidden_roots=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -n "$hidden_roots" ]; then
    printTime "WARNING: Hidden UID 0 users found: $hidden_roots"
    for hidden_user in $hidden_roots; do
        sed -i "/^$hidden_user:/s/^/#/" /etc/passwd
        printTime "Commented out hidden root user: $hidden_user"
    done
fi

# Check for empty passwords
empty_passwords=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
if [ -n "$empty_passwords" ]; then
    printTime "WARNING: Users with empty passwords: $empty_passwords"
    for empty_user in $empty_passwords; do
        passwd -l "$empty_user"
        printTime "Locked user with empty password: $empty_user"
    done
fi

# Final system update
apt-get update
apt-get upgrade -y
apt-get autoremove -y --purge
apt-get autoclean

# Set proper permissions on generated files
chmod 600 "$HOME/Desktop/Script.log"
chmod 700 "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"
chmod 600 "$BACKUP_DIR"/* "$LOG_DIR"/* "$COMP_DIR"/* 2>/dev/null || true

# =============================================
# COMPLETION
# =============================================

printTime "=== HARDENING COMPLETE ==="
printTime "Script execution finished successfully"
printTime "Backups: $BACKUP_DIR"
printTime "Logs: $LOG_DIR"
printTime "Forensic data: $COMP_DIR"
printTime "Main log: $HOME/Desktop/Script.log"

echo ""
echo "=== CYBERPATRIOT HARDENING COMPLETE ==="
echo "Check all log files for details"
echo "System should be rebooted to apply all changes"
echo "Remember to check competition guidelines for specific requirements"

# Optional: Reboot prompt
echo ""
echo "Reboot system now? (yes/no)"
read reboot_choice
if [ "$reboot_choice" = "yes" ]; then
    shutdown -r now
fi
