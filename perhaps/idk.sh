#!/usr/bin/env bash
# =============================================
# CYBERPATRIOT ULTIMATE HARDENING - Interactive
# Target: Ubuntu 20.04+ and Linux Mint 20+
# Version: 3.2-interactive
# =============================================

set -euo pipefail
IFS=$'\n\t'
clear

# ------------------------
# Script metadata & times
# ------------------------
SCRIPT_NAME="CyberPatriot_Ultimate_Hardening"
SCRIPT_VERSION="3.2-interactive"
startTime=$(date +"%s")

# ------------------------
# Paths & dirs (root's Desktop for root user)
# ------------------------
BACKUP_DIR="${BACKUP_DIR:-$HOME/Desktop/backups}"
LOG_DIR="${LOG_DIR:-$HOME/Desktop/logs}"
COMP_DIR="${COMP_DIR:-$HOME/Desktop/Comparatives}"
MAIN_LOG="${MAIN_LOG:-$HOME/Desktop/Script.log}"

mkdir -p -- "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR"
chmod 700 -- "$BACKUP_DIR" "$LOG_DIR" "$COMP_DIR" || true
: > "$MAIN_LOG"
chmod 600 "$MAIN_LOG" || true

# ------------------------
# Utilities
# ------------------------
printTime() {
    local msg="$1"
    local endTime=$(( $(date +%s) - startTime ))
    local min=$((endTime / 60))
    local sec=$((endTime % 60))
    if [ "$min" -lt 10 ]; then
        printf "0%d:%02d -- %s\n" "$min" "$sec" "$msg" | tee -a "$MAIN_LOG"
    else
        printf "%d:%02d -- %s\n" "$min" "$sec" "$msg" | tee -a "$MAIN_LOG"
    fi
}

# Create a timestamped backup of a file/dir if it exists
backup_file() {
    local src="$1"
    if [ -e "$src" ]; then
        local stamp
        stamp=$(date +"%Y%m%d_%H%M%S")
        local dest="$BACKUP_DIR/$(basename "$src").${stamp}"
        cp -a -- "$src" "$dest" 2>/dev/null && printTime "Backed up $src -> $dest" || printTime "Backup failed for $src"
    else
        printTime "backup_file: $src not found, skipping"
    fi
}

# Append a line to a file if it doesn't already exist (idempotent)
ensure_line_in_file() {
    local line="$1"
    local file="$2"
    mkdir -p -- "$(dirname "$file")"
    touch -- "$file"
    if ! grep -Fxq -- "$line" "$file"; then
        echo "$line" >> "$file"
        printTime "Appended line to $file"
    else
        printTime "Line already present in $file"
    fi
}

# Append a block to a file if a unique marker isn't present
ensure_block_in_file() {
    local marker="$1"; local file="$2"; shift 2
    local block="$*"
    mkdir -p -- "$(dirname "$file")"
    touch -- "$file"
    if ! grep -Fq -- "$marker" "$file"; then
        printf "\n# %s\n%s\n" "$marker" "$block" >> "$file"
        printTime "Appended block ($marker) to $file"
    else
        printTime "Block ($marker) already present in $file"
    fi
}

# Safe chmod: only if exists
safe_chmod() {
    [ -e "$1" ] && chmod "$2" "$1" && printTime "chmod $2 $1" || printTime "safe_chmod: $1 not found"
}

# Detect OS and version
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        printf "%s %s\n" "$NAME" "$VERSION_ID"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -d -r
    else
        echo "Unknown OS"
    fi
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi
printTime "Script running as root."

# ------------------------
# INITIAL SYSTEM CHECKS
# ------------------------
printTime "=== INITIAL SYSTEM CHECKS ==="
read -r OS VER <<< "$(detect_os)"
printTime "Detected OS: $OS $VER"

printTime "Gathering initial system information..."
{
    echo '=== APT SOURCES ==='
    grep -h "^deb" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    echo '=== SUDOERS (non-comment lines) ==='
    awk '!/^#/' /etc/sudoers 2>/dev/null || true
} >> "$MAIN_LOG"

# ------------------------
# BACKUP CRITICAL FILES
# ------------------------
printTime "=== BACKING UP CRITICAL FILES ==="
backup_files=(
    "/etc/passwd" "/etc/group" "/etc/shadow" "/etc/sudoers"
    "/etc/ssh/sshd_config" "/etc/sysctl.conf" "/etc/pam.d/common-auth"
    "/etc/pam.d/common-password" "/etc/login.defs" "/etc/hosts"
    "/etc/lightdm/lightdm.conf" "/etc/apache2/apache2.conf" "/etc/mysql/my.cnf"
    "/etc/samba/smb.conf" "/etc/vsftpd.conf" "/etc/rc.local"
)
for f in "${backup_files[@]}"; do
    backup_file "$f"
done

# ------------------------
# PACKAGE MANAGEMENT & SYSTEM UPDATE
# ------------------------
printTime "=== PACKAGE MANAGEMENT ==="
export DEBIAN_FRONTEND=noninteractive

apt-get update -y || apt-get update || true
# Use upgrade to minimize disruptive dependency changes for competition images
apt-get -y upgrade || true
apt-get -y install -f || true
apt-get -y autoremove --purge || true
apt-get -y autoclean || true
apt-get check || true

# Configure automatic updates (idempotent)
cat > /etc/apt/apt.conf.d/10periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
printTime "Automatic updates configured"

# Ensure net-tools present if script uses netstat (we prefer ss)
apt-get -y install net-tools >/dev/null 2>&1 || true

# ------------------------
# REMOVE HIGH-RISK PACKAGES (prompted, interactive)
# ------------------------
printTime "=== CHECK FOR HIGH-RISK PACKAGES ==="
high_risk_packages=(
    john hydra aircrack-ng ophcrack fcrackzip pyrit rarcrack
    logkeys nmap zenmap wireshark netcat-openbsd socat
    metasploit-framework medusa cryptcat tightvncserver x11vnc
    nfs-kernel-server rpcbind xinetd inetd inetutils-telnetd snmp
)
for pkg in "${high_risk_packages[@]}"; do
    if dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        read -r -p "Package '$pkg' is installed. Purge it? (yes/no) [no]: " ans
        ans=${ans:-no}
        if [ "$ans" = "yes" ]; then
            apt-get -y purge "$pkg" || printTime "Failed to purge $pkg (continuing)"
        else
            printTime "Skipping purge of $pkg"
        fi
    fi
done
# Remove certain common desktop games (non-fatal if absent)
apt-get -y purge --allow-change-held-packages aisleriot gnome-mahjongg gnome-mines gnome-sudoku || true

# ------------------------
# USER ACCOUNT MANAGEMENT (interactive)
# ------------------------
printTime "=== USER ACCOUNT MANAGEMENT ==="
echo "Type existing user account names to manage (space separated), or press Enter to skip:"
read -r -a users || true

STATIC_PW="CyberPatriot2024!"  # as requested: static password

for user in "${users[@]:-}"; do
    if id "$user" &>/dev/null; then
        read -r -p "Delete user $user? (yes/no) [no]: " del_yn
        del_yn=${del_yn:-no}
        if [ "$del_yn" = "yes" ]; then
            # Protect current operator
            if [ "$user" = "$SUDO_USER" ] || [ "$user" = "$(whoami)" ]; then
                printTime "Skipping deletion of current operator user $user"
            else
                userdel -r "$user" && printTime "Deleted user: $user" || printTime "Failed to delete $user"
            fi
            continue
        fi

        read -r -p "Make $user administrator? (yes/no) [no]: " admin_yn
        admin_yn=${admin_yn:-no}
        if [ "$admin_yn" = "yes" ]; then
            usermod -aG sudo,adm,lpadmin,sambashare "$user" && printTime "Made $user administrator" || printTime "Failed to add $user to admin groups"
        else
            # Remove from admin groups if present (best-effort)
            for grp in sudo adm lpadmin sambashare; do
                if getent group "$grp" >/dev/null 2>&1; then
                    gpasswd -d "$user" "$grp" 2>/dev/null || true
                fi
            done
            printTime "Ensured $user is a standard user (removed admin groups)"
        fi

        read -r -p "Set custom password for $user? (yes/no) [no]: " pass_yn
        pass_yn=${pass_yn:-no}
        if [ "$pass_yn" = "yes" ]; then
            echo "Enter new password for $user:"
            read -r -s user_pass
            echo
            printf "%s\n%s\n" "$user_pass" "$user_pass" | passwd "$user" && printTime "Set custom password for $user" || printTime "Failed to set password for $user"
        else
            printf "%s\n%s\n" "$STATIC_PW" "$STATIC_PW" | passwd "$user" && printTime "Set static password for $user" || printTime "Failed to set static password for $user"
        fi

        # Apply expiration policy (do not lock by default)
        passwd -x 30 -n 3 -w 7 "$user" || printTime "Failed to set expiration for $user"
        printTime "Applied password policy for $user"
    else
        printTime "User $user not found"
    fi
done

# Create new users interactively
read -r -p "Create new users? (yes/no) [no]: " create_new
create_new=${create_new:-no}
if [ "$create_new" = "yes" ]; then
    echo "Type new user account names (space separated):"
    read -r -a new_users || true
    for new_user in "${new_users[@]:-}"; do
        if id "$new_user" &>/dev/null; then
            printTime "User $new_user already exists, skipping"
            continue
        fi
        adduser --gecos "" --disabled-password "$new_user" && printTime "Added user $new_user" || printTime "Failed to add $new_user"
        printf "%s\n%s\n" "$STATIC_PW" "$STATIC_PW" | passwd "$new_user" || printTime "Failed to set password for $new_user"
        passwd -x 30 -n 3 -w 7 "$new_user" || true
        printTime "Created and applied policy to $new_user"
    done
fi

# ------------------------
# SERVICE CONFIGURATION (interactive)
# ------------------------
printTime "=== SERVICE CONFIGURATION ==="
read -r -p "Does this machine need Samba? (yes/no) [no]: " sambaYN
sambaYN=${sambaYN:-no}
read -r -p "Does this machine need FTP? (yes/no) [no]: " ftpYN
ftpYN=${ftpYN:-no}
read -r -p "Does this machine need SSH? (yes/no) [yes]: " sshYN
sshYN=${sshYN:-yes}
read -r -p "Does this machine need Telnet? (yes/no) [no]: " telnetYN
telnetYN=${telnetYN:-no}
read -r -p "Does this machine need Mail? (yes/no) [no]: " mailYN
mailYN=${mailYN:-no}
read -r -p "Does this machine need Printing? (yes/no) [no]: " printYN
printYN=${printYN:-no}
read -r -p "Does this machine need MySQL? (yes/no) [no]: " dbYN
dbYN=${dbYN:-no}
read -r -p "Will this machine be a Web Server? (yes/no) [no]: " httpYN
httpYN=${httpYN:-no}
read -r -p "Does this machine need DNS? (yes/no) [no]: " dnsYN
dnsYN=${dnsYN:-no}
read -r -p "Does this machine allow media files? (yes/no) [yes]: " mediaFilesYN
mediaFilesYN=${mediaFilesYN:-yes}

# -----------------------
# SSH configuration
# -----------------------
if [ "$sshYN" = "no" ]; then
    printTime "Operator chose: remove/disable SSH"
    ufw --force deny ssh || true
    apt-get -y purge openssh-server || true
    printTime "SSH removed/blocked"
else
    apt-get -y install openssh-server || true
    ufw allow ssh || true

    backup_file "/etc/ssh/sshd_config"
    cat > /etc/ssh/sshd_config <<'EOF'
# CyberPatriot SSH Configuration
Protocol 2
Port 22
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UsePAM yes
EOF

    # If operator provided users earlier, set AllowUsers; otherwise leave unset
    if [ "${#users[@]}" -gt 0 ]; then
        sed -i '/^AllowUsers/d' /etc/ssh/sshd_config || true
        printf 'AllowUsers %s\n' "${users[*]}" >> /etc/ssh/sshd_config
        printTime "Set AllowUsers in sshd_config"
    fi

    # Validate and restart sshd
    if command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>/dev/null; then
            systemctl restart sshd || systemctl restart ssh || printTime "Restarted sshd"
        else
            printTime "sshd config test failed; please inspect /etc/ssh/sshd_config"
        fi
    fi
    printTime "SSH hardened"
fi

# -----------------------
# Web Server (Apache)
# -----------------------
if [ "$httpYN" = "no" ]; then
    ufw --force deny http || true
    ufw --force deny https || true
    apt-get -y purge apache2 nginx || true
    printTime "Web servers removed/blocked"
else
    apt-get -y install apache2 || true
    ufw allow http || true
    ufw allow https || true

    backup_file "/etc/apache2/apache2.conf"
    ensure_line_in_file "ServerTokens Prod" /etc/apache2/apache2.conf
    ensure_line_in_file "ServerSignature Off" /etc/apache2/apache2.conf
    ensure_block_in_file "CYBERPATRIOT-DENY-ROOT-DIR" /etc/apache2/apache2.conf '<Directory />\n    AllowOverride None\n    Require all denied\n</Directory>'
    systemctl restart apache2 || true
    printTime "Apache installed/secured"
fi

# -----------------------
# MySQL / MariaDB
# -----------------------
if [ "$dbYN" = "no" ]; then
    ufw --force deny mysql || true
    apt-get -y purge mysql-server mariadb-server || true
    printTime "MySQL/MariaDB removed"
else
    apt-get -y install mysql-server || true
    ufw allow mysql || true
    backup_file "/etc/mysql/my.cnf"
    # Ensure bind-address is localhost
    if [ -f /etc/mysql/my.cnf ]; then
        if grep -q "^bind-address" /etc/mysql/my.cnf 2>/dev/null; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf || true
        else
            echo "bind-address = 127.0.0.1" >> /etc/mysql/my.cnf
        fi
    fi

    # Attempt a non-interactive secure configuration using SQL statements (best-effort)
    if command -v mysql >/dev/null 2>&1; then
        # Set root password and remove anonymous/test DBs if possible
        mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${STATIC_PW}'; DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;" >/dev/null 2>&1 || printTime "mysql_secure steps partially failed - run mysql_secure_installation interactively"
    else
        printTime "MySQL client not found; please run mysql_secure_installation manually"
    fi
    printTime "MySQL installed/attempted secure steps"
fi

# ------------------------
# SECURITY HARDENING
# ------------------------
printTime "=== SECURITY HARDENING ==="

# File permissions (safe checks)
[ -f /etc/shadow ] && safe_chmod /etc/shadow 640
safe_chmod /etc/passwd 644
safe_chmod /etc/group 644
[ -f /etc/apt/sources.list ] && safe_chmod /etc/apt/sources.list 644

# Home dirs: be conservative
for d in /home/*; do
    [ -d "$d" ] && safe_chmod "$d" 700 || true
done

# Secure sudoers (append safe defaults only if not present)
ensure_line_in_file "Defaults authenticate" /etc/sudoers
ensure_line_in_file "Defaults use_pty" /etc/sudoers
ensure_line_in_file "Defaults timestamp_timeout=5" /etc/sudoers

# Configure UFW (force enable)
ufw --force enable || true
ufw default deny incoming || true
ufw default allow outgoing || true
ufw deny 1337 || true

# iptables-persistent (best-effort)
apt-get -y install iptables-persistent || true

# Basic iptables rules (kept simple)
iptables -F || true
iptables -X || true
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow services based on choices
if [ "$sshYN" = "yes" ]; then iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 22 -j ACCEPT; fi
if [ "$httpYN" = "yes" ]; then iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 80 -j ACCEPT; fi
if [ "$httpYN" = "yes" ]; then iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport 443 -j ACCEPT; fi

iptables-save > /etc/iptables/rules.v4 || true

# Sysctl hardening (append only if not present)
backup_file "/etc/sysctl.conf"
ensure_block_in_file "CYBERPATRIOT-SYSCTL" /etc/sysctl.conf '
# Network security
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
# Kernel security
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
'

sysctl -p || true

# PAM configuration (modern)
apt-get -y install libpam-pwquality libpam-pwquality || true
backup_file "/etc/pam.d/common-password"
cat > /etc/pam.d/common-password <<'EOF'
# CyberPatriot PAM Configuration
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password requisite pam_pwhistory.so use_authtok remember=5
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
EOF
printTime "PAM configuration applied"

# Login defns
if [ -f /etc/login.defs ]; then
    sed -i 's/^[[:space:]]*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs || true
    sed -i 's/^[[:space:]]*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs || true
    sed -i 's/^[[:space:]]*PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs || true
fi

# ------------------------
# FILE SYSTEM SECURITY
# ------------------------
printTime "=== FILE SYSTEM SECURITY ==="

if [ "$mediaFilesYN" = "no" ]; then
    printTime "Operator chose to remove media files from /home (destructive)."
    read -r -p "Type YES to permanently delete media files from /home (uppercase YES): " confirm_media
    if [ "$confirm_media" = "YES" ]; then
        # Find under /home only; exclude system FS to speed up and avoid /proc etc.
        find /home -xdev -type f \( -iname "*.mp3" -o -iname "*.wav" -o -iname "*.flac" -o -iname "*.m4a" -o -iname "*.ogg" \) -delete 2>/dev/null || true
        find /home -xdev -type f \( -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mov" -o -iname "*.mkv" -o -iname "*.flv" \) -delete 2>/dev/null || true
        find /home -xdev -type f \( -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.bmp" \) -delete 2>/dev/null || true
        printTime "Media files removed from home directories"
    else
        printTime "Media removal skipped"
    fi
fi

# Suspicious files search (avoid /proc, /sys)
printTime "Searching for suspicious files (SUID/SGID, world-writable, no-owner, php files)..."
find / -xdev -type f -perm /6000 > "$LOG_DIR/suid_sgid_files.log" 2>/dev/null || true
find / -xdev -type f -perm /o+w > "$LOG_DIR/world_writable_files.log" 2>/dev/null || true
find / -xdev -nouser -o -nogroup > "$LOG_DIR/no_owner_files.log" 2>/dev/null || true
find / -xdev -name "*.php" -type f > "$LOG_DIR/php_files.log" 2>/dev/null || true

# Do NOT delete /bin/*.sh — keep system integrity
printTime "Skipped deletion of system shell scripts (safe-guard)."

# Secure critical directories and histories
safe_chmod /root 700
[ -f /root/.bash_history ] && safe_chmod /root/.bash_history 600
for h in /home/*/.bash_history; do [ -f "$h" ] && safe_chmod "$h" 600 || true; done

# ------------------------
# SECURITY TOOLS & MONITORING
# ------------------------
printTime "=== SECURITY TOOLS ==="
apt-get -y install chkrootkit rkhunter clamav fail2ban auditd unattended-upgrades libpam-pwquality || true

# Update ClamAV db if available
if command -v freshclam >/dev/null 2>&1; then
    freshclam || printTime "freshclam encountered issues (network or permissions)"
fi

systemctl enable --now fail2ban || true
systemctl enable --now auditd || true

# Run rkhunter/chkrootkit in best-effort mode
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --update || true
    rkhunter --check --sk --rwo >> "$MAIN_LOG" 2>&1 || true
fi
if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit >> "$MAIN_LOG" 2>&1 || true
fi
printTime "Security tools installed/checked"

# ------------------------
# FORENSIC DATA COLLECTION
# ------------------------
printTime "=== FORENSIC DATA COLLECTION ==="
uname -a > "$COMP_DIR/system_info.txt"
[ -f /etc/os-release ] && cat /etc/os-release >> "$COMP_DIR/system_info.txt" 2>/dev/null || true
getent passwd > "$COMP_DIR/all_users.txt" 2>/dev/null || true
getent group > "$COMP_DIR/all_groups.txt" 2>/dev/null || true
lastlog > "$COMP_DIR/last_logins.txt" 2>/dev/null || true
ps aux > "$COMP_DIR/processes.txt" 2>/dev/null || true
systemctl list-unit-files --type=service > "$COMP_DIR/services.txt" 2>/dev/null || true
ss -tuln > "$COMP_DIR/listening_ports.txt" 2>/dev/null || true
if command -v netstat >/dev/null 2>&1; then netstat -tuln > "$COMP_DIR/network_connections.txt" 2>/dev/null || true; fi
dpkg -l > "$COMP_DIR/installed_packages.txt" 2>/dev/null || true
apt-mark showmanual > "$COMP_DIR/manual_packages.txt" 2>/dev/null || true
find / -xdev -type f -perm /777 > "$COMP_DIR/world_writable_files.txt" 2>/dev/null || true
find / -xdev -name ".*" -type f > "$COMP_DIR/hidden_files.txt" 2>/dev/null || true
ufw status verbose > "$COMP_DIR/ufw_status.txt" 2>/dev/null || true
[ -f /etc/ssh/sshd_config ] && cat /etc/ssh/sshd_config > "$COMP_DIR/ssh_config.txt" 2>/dev/null || true

# ------------------------
# COMPETITION-SPECIFIC ENHANCEMENTS
# ------------------------
printTime "=== COMPETITION ENHANCEMENTS ==="
ensure_line_in_file "blacklist usb-storage" /etc/modprobe.d/blacklist.conf
ensure_line_in_file 'install firewire-core /bin/true' /etc/modprobe.d/firewire.conf
ensure_line_in_file 'install thunderbolt /bin/true' /etc/modprobe.d/thunderbolt.conf

# GRUB security — do not set incomplete password; instruct operator
backup_file "/boot/grub/grub.cfg"
safe_chmod /boot/grub/grub.cfg 600 || true
ensure_block_in_file "CYBERPATRIOT-GRUB" /etc/grub.d/40_custom 'set superusers="root"
# To enable GRUB password, replace <GRUB_PBKDF2_HASH> below with a valid pbkdf2 hash:
# password_pbkdf2 root <GRUB_PBKDF2_HASH>'
update-grub >/dev/null 2>&1 || true

# Login banners
printf "%s\n" "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue
printf "%s\n" "WARNING: Unauthorized access prohibited. All activities are monitored." > /etc/issue.net

# Secure cron/at — restrict to root
printf "root\n" > /etc/cron.allow
printf "root\n" > /etc/at.allow
safe_chmod /etc/cron.allow 600
safe_chmod /etc/at.allow 600
# Do not overly restrict /etc/crontab permission by default; keep 644
safe_chmod /etc/crontab 644 || true
chmod 600 /etc/cron.*/* 2>/dev/null || true

# Provide a minimal /etc/rc.local with backup
backup_file "/etc/rc.local"
cat > /etc/rc.local <<'EOF'
#!/bin/sh -e
# rc.local - left minimal for compatibility
exit 0
EOF
chmod +x /etc/rc.local || true

# ------------------------
# FINAL CHECKS & CLEANUP
# ------------------------
printTime "=== FINAL CHECKS ==="
# Hidden UID 0 users
hidden_roots=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd || true)
if [ -n "$hidden_roots" ]; then
    printTime "WARNING: Hidden UID 0 users found: $hidden_roots"
    while read -r hidden_user; do
        sed -i "/^${hidden_user}:/s/^/#/" /etc/passwd || true
        printTime "Commented out hidden root user: $hidden_user"
    done <<< "$hidden_roots"
fi

# Empty password fields
empty_passwords=$(awk -F: '($2=="" ) {print $1}' /etc/shadow || true)
if [ -n "$empty_passwords" ]; then
    printTime "WARNING: Users with empty password field: $empty_passwords"
    while read -r empty_user; do
        passwd -l "$empty_user" || true
        printTime "Locked user with empty password: $empty_user"
    done <<< "$empty_passwords"
fi

# Final apt housekeeping
apt-get update -y || true
apt-get -y upgrade || true
apt-get -y autoremove --purge || true
apt-get -y autoclean || true

# Permissions on generated files
safe_chmod "$MAIN_LOG" 600
safe_chmod "$BACKUP_DIR" 700 || true
safe_chmod "$LOG_DIR" 700 || true
safe_chmod "$COMP_DIR" 700 || true
chmod 600 "$BACKUP_DIR"/* "$LOG_DIR"/* "$COMP_DIR"/* 2>/dev/null || true

# Completion
printTime "=== HARDENING COMPLETE ==="
printTime "Script execution finished successfully"
printTime "Backups: $BACKUP_DIR"
printTime "Logs: $LOG_DIR"
printTime "Forensic data: $COMP_DIR"
printTime "Main log: $MAIN_LOG"

echo ""
echo "=== CYBERPATRIOT HARDENING COMPLETE ==="
echo "Check all log files for details"
echo "System should be rebooted to apply all changes"

read -r -p "Reboot system now? (yes/no) [no]: " reboot_choice
reboot_choice=${reboot_choice:-no}
if [ "$reboot_choice" = "yes" ]; then
    shutdown -r now
fi

exit 0

