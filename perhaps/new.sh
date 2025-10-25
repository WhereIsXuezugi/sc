#!/bin/bash

# =============================================
# COMPREHENSIVE CYBERPATRIOT HARDENING SCRIPT
# For Ubuntu 20.04+ and Linux Mint 20+
# Competition Ready - All Fixes Applied
# =============================================

set -euo pipefail
clear

# =============================================
# INITIALIZATION & LOGGING
# =============================================

# Script meta
SCRIPT_NAME="CyberPatriot_Ultimate_Hardening"
SCRIPT_VERSION="4.1"
startTime=$(date +"%s")

# Directories
BACKUP_DIR="$HOME/Desktop/backups"
LOG_DIR="$HOME/Desktop/logs"
COMP_DIR="$HOME/Desktop/Comparatives"

# Create directories
mkdir -p "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"
chmod 700 "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"

# Main log file
SCRIPT_LOG="$HOME/Desktop/Script.log"
touch "$SCRIPT_LOG"
echo "=== CyberPatriot Hardening Script Started $(date) ===" > "$SCRIPT_LOG"
chmod 600 "$SCRIPT_LOG"

# Enhanced timing function with proper error handling
printTime() {
    local message="$1"
    local currentTime=$(date +%s)
    local elapsed=$((currentTime - startTime))
    printf "%02d:%02d -- %s\n" $((elapsed/60)) $((elapsed%60)) "$message" | tee -a "$SCRIPT_LOG"
}

# Error handler
error_handler() {
    local exit_code=$1
    local line_no=$2
    printTime "ERROR: Script failed at line $line_no with exit code $exit_code"
    exit $exit_code
}
trap 'error_handler $? $LINENO' ERR

# =============================================
# PRE-FLIGHT CHECKS & VALIDATION
# =============================================

printTime "=== PRE-FLIGHT SYSTEM CHECKS ==="

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root. Use: sudo $0"
    exit 1
fi
printTime "✓ Root privileges confirmed"

# Detect OS and version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    OS=$(lsb_release -si 2>/dev/null || echo "Unknown")
    VER=$(lsb_release -sr 2>/dev/null || echo "Unknown")
fi
printTime "✓ Detected OS: $OS $VER"

# Validate environment
validate_environment() {
    if ! command -v apt-get &> /dev/null; then
        echo "ERROR: This script requires apt-based system (Ubuntu/Mint)"
        exit 1
    fi
    
    if [ ! -d /home ]; then
        echo "ERROR: /home directory not found"
        exit 1
    fi
    
    printTime "✓ Environment validation passed"
}
validate_environment

# Initial system information
printTime "Gathering initial system information..."
{
    echo "=== SYSTEM INFORMATION ==="
    uname -a
    echo "=== OS RELEASE ==="
    cat /etc/os-release 2>/dev/null || true
    echo "=== APT SOURCES ==="
    grep -h "^deb" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    echo "=== SUDOERS CONFIG ==="
    grep -v "^#" /etc/sudoers | grep -v "^$" 2>/dev/null || true
} >> "$SCRIPT_LOG"

# =============================================
# COMPREHENSIVE BACKUP SYSTEM
# =============================================

printTime "=== CREATING SYSTEM BACKUPS ==="

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
    "/etc/fstab"
    "/etc/crontab"
)

for file in "${backup_files[@]}"; do
    if [ -f "$file" ]; then
        if cp "$file" "$BACKUP_DIR/$(basename "$file").backup.$(date +%Y%m%d)" 2>/dev/null; then
            printTime "✓ Backed up $file"
            echo "$file" >> "$BACKUP_DIR/backup_manifest.txt"
        else
            printTime "⚠ Could not backup $file"
        fi
    fi
done

# =============================================
# PACKAGE MANAGEMENT & SYSTEM UPDATE
# =============================================

printTime "=== SYSTEM UPDATE & PACKAGE MANAGEMENT ==="

# Update package lists
if apt-get update -y; then
    printTime "✓ Package lists updated"
else
    printTime "⚠ Package list update had issues"
fi

# Full system upgrade
printTime "Performing system upgrade..."
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
printTime "✓ Automatic updates configured"

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
    "vnc4server" "vncsnapshot" "vtgrab" "snmp" "zeigeist-core" "zeigeist-datahub"
    "python-zeitgeist" "rhythmbox-plugin-zeitgeist" "zeitgeist"
)

for pkg in "${high_risk_packages[@]}"; do
    if dpkg -l | grep -q "^ii  $pkg "; then
        if apt-get purge -y "$pkg"; then
            printTime "✓ Removed: $pkg"
        else
            printTime "⚠ Failed to remove: $pkg"
        fi
    fi
done

# Remove games and unnecessary packages
games_packages=(
    "aisleriot" "gnome-mahjongg" "gnome-mines" "gnome-sudoku" 
    "gnome-cards" "gnome-chess" "gnome-games" "supertux" 
    "supertuxkart" "frozen-bubble" "xpenguins"
)

for game in "${games_packages[@]}"; do
    if dpkg -l | grep -q "^ii  $game "; then
        apt-get purge -y "$game" && printTime "✓ Removed game: $game" || true
    fi
done

# Clean up
apt-get autoremove -y --purge
apt-get autoclean

# =============================================
# INTERACTIVE SERVICE CONFIGURATION
# =============================================

printTime "=== SERVICE CONFIGURATION ==="

# Service prompts with validation
while true; do
    read -p "Does this machine need Samba? (yes/no): " sambaYN
    case $sambaYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need FTP? (yes/no): " ftpYN
    case $ftpYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need SSH? (yes/no): " sshYN
    case $sshYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need Telnet? (yes/no): " telnetYN
    case $telnetYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need Mail? (yes/no): " mailYN
    case $mailYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need Printing? (yes/no): " printYN
    case $printYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need MySQL? (yes/no): " dbYN
    case $dbYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Will this machine be a Web Server? (yes/no): " httpYN
    case $httpYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine need DNS? (yes/no): " dnsYN
    case $dnsYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

while true; do
    read -p "Does this machine allow media files? (yes/no): " mediaFilesYN
    case $mediaFilesYN in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

# SSH Configuration
if [ "$sshYN" = "no" ]; then
    systemctl stop ssh 2>/dev/null || true
    if dpkg -l | grep -q openssh-server; then
        apt-get purge -y openssh-server
        printTime "✓ SSH removed"
    fi
else
    # Stop service before configuration
    systemctl stop ssh 2>/dev/null || true
    
    if ! dpkg -l | grep -q openssh-server; then
        apt-get install -y openssh-server
    fi
    
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
PasswordAuthentication yes  # FIXED: Enabled for competition flexibility
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

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

# User restrictions
AllowUsers
EOF

    if sshd -t; then
        systemctl start ssh  # FIXED: Start service after configuration
        printTime "✓ SSH hardened and restarted"
    else
        printTime "⚠ SSH config test failed, using backup"
        cp "$BACKUP_DIR/sshd_config.backup" /etc/ssh/sshd_config 2>/dev/null || true
        systemctl start ssh
    fi
fi

# Web Server Configuration
if [ "$httpYN" = "no" ]; then
    systemctl stop apache2 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    apt-get purge -y apache2 nginx
    printTime "✓ Web servers removed"
else
    # Stop service before configuration
    systemctl stop apache2 2>/dev/null || true
    
    if ! dpkg -l | grep -q apache2; then
        apt-get install -y apache2
    fi
    
    # Secure Apache
    if [ -f /etc/apache2/apache2.conf ]; then
        backup_file "/etc/apache2/apache2.conf"
        echo -e "\n<Directory />\nAllowOverride None\nOrder Deny,Allow\nDeny from all\n</Directory>" >> /etc/apache2/apache2.conf
        echo "ServerTokens Prod" >> /etc/apache2/apache2.conf
        echo "ServerSignature Off" >> /etc/apache2/apache2.conf
        systemctl start apache2  # FIXED: Start service after configuration
        printTime "✓ Apache secured"
    fi
fi

# MySQL Configuration
if [ "$dbYN" = "no" ]; then
    systemctl stop mysql 2>/dev/null || true
    if dpkg -l | grep -q mysql-server; then
        apt-get purge -y mysql-server mysql-client mysql-common
        printTime "✓ MySQL removed"
    fi
else
    # Stop service before configuration
    systemctl stop mysql 2>/dev/null || true
    
    if ! dpkg -l | grep -q mysql-server; then
        apt-get install -y mysql-server
    fi
    
    # Secure MySQL
    if [ -f /etc/mysql/my.cnf ]; then
        backup_file "/etc/mysql/my.cnf"
        if ! grep -q "bind-address" /etc/mysql/my.cnf; then
            echo "bind-address = 127.0.0.1" >> /etc/mysql/my.cnf
        fi
        systemctl start mysql  # FIXED: Start service after configuration
        printTime "✓ MySQL secured"
    fi
fi

# Samba Configuration
if [ "$sambaYN" = "no" ]; then
    systemctl stop smbd 2>/dev/null || true
    systemctl stop nmbd 2>/dev/null || true
    apt-get purge -y samba samba-common samba-common-bin
    printTime "✓ Samba removed"
else
    systemctl stop smbd 2>/dev/null || true
    systemctl stop nmbd 2>/dev/null || true
    
    if ! dpkg -l | grep -q samba; then
        apt-get install -y samba
    fi
    printTime "✓ Samba configured"
    systemctl start smbd 2>/dev/null || true
    systemctl start nmbd 2>/dev/null || true
fi

# =============================================
# CONSOLIDATED FIREWALL CONFIGURATION
# =============================================

printTime "=== CONFIGURING FIREWALL (CONSOLIDATED) ==="

configure_firewall_consolidated() {
    # Reset to avoid conflicts
    ufw --force reset
    
    # Set defaults
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow services based on configuration
    [ "$sshYN" = "yes" ] && ufw allow ssh
    [ "$httpYN" = "yes" ] && ufw allow http
    [ "$httpYN" = "yes" ] && ufw allow https
    [ "$dbYN" = "yes" ] && ufw allow mysql
    
    # Samba ports if enabled
    if [ "$sambaYN" = "yes" ]; then
        ufw allow 139/tcp
        ufw allow 445/tcp
        ufw allow 137/udp
        ufw allow 138/udp
    fi
    
    # Deny risky ports
    ufw deny 1337
    ufw deny 23    # telnet
    ufw deny 513   # rlogin
    
    # Enable firewall
    ufw --force enable
    printTime "✓ UFW firewall configured without conflicts"
}

# Call consolidated firewall function
configure_firewall_consolidated

# =============================================
# USER ACCOUNT MANAGEMENT
# =============================================

printTime "=== USER ACCOUNT MANAGEMENT ==="

# Interactive user management
echo "Type existing user account names to manage (space separated, or press enter to skip):"
read -a users

user_processed=false
for user in "${users[@]}"; do
    if id "$user" &>/dev/null; then
        user_processed=true
        while true; do
            read -p "Delete user $user? (yes/no): " del_yn
            case $del_yn in
                yes|no) break ;;
                *) echo "Please answer yes or no." ;;
            esac
        done
        
        if [ "$del_yn" = "yes" ]; then
            if userdel -r "$user"; then
                printTime "✓ Deleted user: $user"
            else
                printTime "⚠ Failed to delete user: $user"
            fi
        else
            while true; do
                read -p "Make $user administrator? (yes/no): " admin_yn
                case $admin_yn in
                    yes|no) break ;;
                    *) echo "Please answer yes or no." ;;
                esac
            done
            
            if [ "$admin_yn" = "yes" ]; then
                usermod -aG sudo,adm,lpadmin "$user"
                printTime "✓ Made $user administrator"
            else
                gpasswd -d "$user" sudo 2>/dev/null || true
                gpasswd -d "$user" adm 2>/dev/null || true
                gpasswd -d "$user" lpadmin 2>/dev/null || true
                printTime "✓ Made $user standard user"
            fi
            
            # Set secure password
            if echo "$user:CyberPatriot2024!" | chpasswd; then
                printTime "✓ Set secure password for $user"
            else
                printTime "⚠ Failed to set password for $user"
            fi
            
            # Apply password policies
            if chage --maxdays 30 --mindays 3 --warndays 7 "$user"; then
                printTime "✓ Applied password policies to $user"
            fi
        fi
    else
        printTime "⚠ User $user not found"
    fi
done

# Create new users if requested
while true; do
    read -p "Create new users? (yes/no): " create_new
    case $create_new in
        yes|no) break ;;
        *) echo "Please answer yes or no." ;;
    esac
done

if [ "$create_new" = "yes" ]; then
    echo "Type new user account names (space separated):"
    read -a new_users
    
    for new_user in "${new_users[@]}"; do
        if adduser --gecos "" --disabled-password "$new_user"; then
            if echo "$new_user:CyberPatriot2024!" | chpasswd; then
                chage --maxdays 30 --mindays 3 --warndays 7 "$new_user"
                printTime "✓ Created and secured user: $new_user"
            fi
        else
            printTime "⚠ Failed to create user: $new_user"
        fi
    done
fi

# =============================================
# SECURITY HARDENING
# =============================================

printTime "=== SYSTEM SECURITY HARDENING ==="

# File permissions
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/apt/sources.list

# Secure home directories
for home_dir in /home/*; do
    if [ -d "$home_dir" ] && [ "$home_dir" != "/home/*" ]; then
        chmod 700 "$home_dir"
        chmod 600 "$home_dir/.bash_history" 2>/dev/null || true
    fi
done

chmod 700 /root
chmod 600 /root/.bash_history

# Sysctl hardening
backup_file "/etc/sysctl.conf"
cat >> /etc/sysctl.conf << 'EOF'

# CyberPatriot Kernel Hardening
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

sysctl -p >/dev/null 2>&1
printTime "✓ Kernel security parameters configured"

# PAM configuration - FIXED: Append instead of replace
if apt-get install -y libpam-cracklib libpam-pwquality; then
    backup_file "/etc/pam.d/common-password"
    
    # Append instead of replace - check if lines exist first
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
    fi
    
    if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
        echo "password requisite pam_pwhistory.so use_authtok remember=5" >> /etc/pam.d/common-password
    fi
    
    printTime "✓ PAM password policies appended to existing configuration"
fi

# Login definitions
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

# Apply to existing users
for user in $(getent passwd {1000..60000} | cut -d: -f1); do
    chage --maxdays 90 --mindays 1 --warndays 7 "$user" 2>/dev/null || true
done

# =============================================
# FILE SYSTEM SECURITY
# =============================================

printTime "=== FILE SYSTEM SECURITY ==="

# Remove media files if not allowed
if [ "$mediaFilesYN" = "no" ]; then
    printTime "Removing media files..."
    
    # Audio files
    find /home -type f \( -name "*.mp3" -o -name "*.wav" -o -name "*.flac" -o -name "*.m4a" -o -name "*.ogg" \) -delete 2>/dev/null || true
    
    # Video files
    find /home -type f \( -name "*.mp4" -o -name "*.avi" -o -name "*.mov" -o -name "*.mkv" -o -name "*.flv" \) -delete 2>/dev/null || true
    
    # Image files
    find /home -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.bmp" \) -delete 2>/dev/null || true
    
    printTime "✓ Media files removed from home directories"
fi

# Find and log suspicious files
printTime "Searching for suspicious files..."
find / -type f -perm /6000 > "$LOG_DIR/suid_sgid_files.log" 2>/dev/null || true
find / -type f -perm /o+w > "$LOG_DIR/world_writable_files.log" 2>/dev/null || true
find / -nouser -o -nogroup > "$LOG_DIR/no_owner_files.log" 2>/dev/null || true
find / -name "*.php" -type f > "$LOG_DIR/php_files.log" 2>/dev/null || true

# Remove dangerous scripts from bin
find /bin/ -name "*.sh" -type f -delete 2>/dev/null || true
printTime "✓ File system security completed"

# =============================================
# SECURITY TOOLS & MONITORING
# =============================================

printTime "=== SECURITY TOOLS INSTALLATION ==="

# Install security tools
security_tools=(
    "chkrootkit"
    "rkhunter"
    "clamav"
    "fail2ban"
    "auditd"
    "unattended-upgrades"
    "lynis"
)

for tool in "${security_tools[@]}"; do
    if apt-get install -y "$tool"; then
        printTime "✓ Installed: $tool"
    else
        printTime "⚠ Failed to install: $tool"
    fi
done

# Update ClamAV
if freshclam; then
    printTime "✓ ClamAV definitions updated"
else
    printTime "⚠ ClamAV update failed"
fi

# Configure fail2ban
systemctl enable fail2ban
systemctl start fail2ban
printTime "✓ Fail2ban configured"

# Configure auditd
systemctl enable auditd
systemctl start auditd
printTime "✓ Auditd configured"

# Run security scans in background
printTime "Running security scans..."
(rkhunter --update && rkhunter --check --sk) >> "$SCRIPT_LOG" 2>&1 &
(chkrootkit) >> "$SCRIPT_LOG" 2>&1 &
printTime "✓ Security scans initiated"

# =============================================
# COMPETITION-SPECIFIC ENHANCEMENTS
# =============================================

printTime "=== COMPETITION ENHANCEMENTS ==="

# Disable unnecessary hardware
echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf
echo 'install firewire-core /bin/true' >> /etc/modprobe.d/firewire.conf
echo 'install thunderbolt /bin/true' >> /etc/modprobe.d/thunderbolt.conf
printTime "✓ Dangerous hardware disabled"

# Secure GRUB - FIXED: Commented out superuser for safety
if [ -f /boot/grub/grub.cfg ]; then
    chmod 600 /boot/grub/grub.cfg
    # FIXED: Commented out to prevent potential lockouts
    # echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    # echo "password_pbkdf2 root grub.pbkdf2.sha512.10000." >> /etc/grub.d/40_custom
    echo "# GRUB superuser configuration commented out for competition safety" >> /etc/grub.d/40_custom
    update-grub
    printTime "✓ GRUB configuration updated (superuser commented out for safety)"
fi

# Configure login banners
echo "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue
echo "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue.net
printTime "✓ Login banners configured"

# Secure cron
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
chmod 600 /etc/crontab
chmod 600 /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null || true
printTime "✓ Cron secured"

# Remove startup scripts
echo 'exit 0' > /etc/rc.local
chmod 744 /etc/rc.local
printTime "✓ Startup scripts secured"

# =============================================
# FORENSIC DATA COLLECTION
# =============================================

printTime "=== FORENSIC DATA COLLECTION ==="

# System information
uname -a > "$COMP_DIR/system_info.txt"
cat /etc/os-release >> "$COMP_DIR/system_info.txt" 2>/dev/null || true

# User information
getent passwd > "$COMP_DIR/all_users.txt"
getent group > "$COMP_DIR/all_groups.txt"
lastlog > "$COMP_DIR/last_logins.txt" 2>/dev/null || true

# Process information
ps aux > "$COMP_DIR/processes.txt"
systemctl list-unit-files --type=service > "$COMP_DIR/services.txt"

# Network information
ss -tuln > "$COMP_DIR/listening_ports.txt"
netstat -tuln > "$COMP_DIR/network_connections.txt" 2>/dev/null || true

# Package information
dpkg -l > "$COMP_DIR/installed_packages.txt"
apt-mark showmanual > "$COMP_DIR/manual_packages.txt" 2>/dev/null || true

# File system information
find / -type f -perm /777 > "$COMP_DIR/world_writable_files.txt" 2>/dev/null || true
find / -name ".*" -type f > "$COMP_DIR/hidden_files.txt" 2>/dev/null || true

# Security configuration
ufw status verbose > "$COMP_DIR/ufw_status.txt"
cat /etc/ssh/sshd_config > "$COMP_DIR/ssh_config.txt" 2>/dev/null || true

printTime "✓ Forensic data collection completed"

# =============================================
# FINAL SECURITY CHECKS
# =============================================

printTime "=== FINAL SECURITY CHECKS ==="

# Check for hidden UID 0 users
hidden_roots=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -n "$hidden_roots" ]; then
    printTime "⚠ WARNING: Hidden UID 0 users found: $hidden_roots"
    for hidden_user in $hidden_roots; do
        sed -i "/^$hidden_user:/s/^/#/" /etc/passwd
        printTime "✓ Commented out hidden root user: $hidden_user"
    done
else
    printTime "✓ No hidden UID 0 users found"
fi

# Check for empty passwords
empty_passwords=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
if [ -n "$empty_passwords" ]; then
    printTime "⚠ WARNING: Users with empty passwords: $empty_passwords"
    for empty_user in $empty_passwords; do
        passwd -l "$empty_user" 2>/dev/null && printTime "✓ Locked user with empty password: $empty_user" || true
    done
else
    printTime "✓ No empty passwords found"
fi

# Final system cleanup
apt-get update
apt-get upgrade -y
apt-get autoremove -y --purge
apt-get autoclean

# Set proper permissions on generated files
find "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR" -type f -exec chmod 600 {} + 2>/dev/null || true
find "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR" -type d -exec chmod 700 {} + 2>/dev/null || true

# =============================================
# COMPLETION & SUMMARY
# =============================================

printTime "=== HARDENING COMPLETE ==="

# Summary
{
    echo ""
    echo "=== CYBERPATRIOT HARDENING SUMMARY ==="
    echo "Backup Directory: $BACKUP_DIR"
    echo "Log Directory: $LOG_DIR"
    echo "Forensic Data: $COMP_DIR"
    echo "Main Log: $SCRIPT_LOG"
    echo ""
    echo "Services Configured:"
    echo "  SSH: $sshYN (Password Authentication: ENABLED)"
    echo "  Web Server: $httpYN"
    echo "  MySQL: $dbYN"
    echo "  Samba: $sambaYN"
    echo "  Media Files: $mediaFilesYN"
    echo ""
    echo "Security Enhancements Applied:"
    echo "  ✓ Firewall configured without conflicts"
    echo "  ✓ PAM policies appended (not replaced)"
    echo "  ✓ GRUB superuser commented out (safe)"
    echo "  ✓ Services properly stopped/started"
    echo ""
    echo "Next Steps:"
    echo "1. Review all log files for any warnings"
    echo "2. Check forensic data for system baseline"
    echo "3. Test essential services"
    echo "4. Reboot system to apply all changes"
    echo "5. Verify competition requirements are met"
} | tee -a "$SCRIPT_LOG"

# Final permissions check
chmod 600 "$SCRIPT_LOG"

printTime "✓ Script execution finished successfully"
printTime "Total execution time: $(($(date +%s) - startTime)) seconds"

# Optional reboot prompt
echo ""
echo "=== SYSTEM READY FOR COMPETITION ==="
echo "Hardening completed successfully!"
echo ""
read -p "Reboot system now to apply all changes? (recommended) [y/N]: " reboot_choice
case "$reboot_choice" in
    [yY]|[yY][eE][sS])
        printTime "System reboot initiated by user"
        shutdown -r now
        ;;
    *)
        echo "Please remember to reboot the system later to apply all changes."
        printTime "System reboot deferred by user"
        ;;
esac

exit 0
