#!/bin/bash

# =============================================
# Comprehensive CyberPatriot System Hardening Script
# Designed for Ubuntu and Linux Mint
# =============================================

# Initialize script with strict error handling
set -euo pipefail
trap 'cleanup $? $LINENO' EXIT ERR SIGINT SIGTERM

# Script meta variables
SCRIPT_NAME="CyberPatriot Hardening Script"
SCRIPT_VERSION="1.0"
LOG_FILE="/var/log/cyberpatriot_hardening.log"
BACKUP_DIR="/root/cyberpatriot_backups"
COMPARATIVE_DIR="/root/cyberpatriot_comparatives"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# =============================================
# FUNCTION LIBRARY
# =============================================

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Error handling function
cleanup() {
    local exit_code=$1
    local line_no=$2
    
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Script failed with exit code $exit_code at line $line_no"
        echo -e "${RED}Script execution failed. Check $LOG_FILE for details.${NC}"
    fi
    
    # Cleanup background processes if any
    pkill -P $$ 2>/dev/null || true
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root. Use sudo.${NC}"
        exit 1
    fi
    log "INFO" "Root privileges confirmed."
}

# Backup original configuration files
backup_file() {
    local file=$1
    local backup_path="$BACKUP_DIR${file}"
    
    if [[ -f "$file" ]]; then
        mkdir -p "$(dirname "$backup_path")"
        cp "$file" "$backup_path"
        log "INFO" "Backed up $file to $backup_path"
    fi
}

# Compare files for forensic analysis
create_comparative() {
    local description=$1
    local command=$2
    local filename=$(echo "$description" | tr ' ' '_' | tr '[A-Z]' '[a-z]')
    
    mkdir -p "$COMPARATIVE_DIR"
    eval "$command" > "$COMPARATIVE_DIR/$filename.txt" 2>&1 || true
}

# =============================================
# PACKAGE MANAGEMENT & AUTOMATED UPDATES
# =============================================

configure_automatic_updates() {
    log "INFO" "Configuring automatic security updates..."
    
    # Install required packages
    apt-get update && apt-get install -y unattended-upgrades apt-listchanges needrestart
    
    # Configure unattended-upgrades
    backup_file "/etc/apt/apt.conf.d/50unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
    # Add packages you never want to update automatically
};
Unattended-Upgrade::AutoFixInterruptedDependencies "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

    # Enable automatic updates
    backup_file "/etc/apt/apt.conf.d/20auto-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    log "INFO" "Automatic security updates configured."
}

remove_prohibited_packages() {
    log "INFO" "Removing potentially dangerous and prohibited packages..."
    
    # Comprehensive list of packages to remove
    local prohibited_packages=(
        "john" "hydra" "ophcrack" "aircrack-ng" "nmap" "netcat" "telnet"
        "samba" "vsftpd" "tightvncserver" "nessus" "metasploit-framework"
        "wireshark" "freeciv" "minetest" "aisleriot" "gnome-mahjongg"
    )
    
    for package in "${prohibited_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            apt-get purge -y "$package" && log "INFO" "Removed package: $package"
        fi
    done
    
    # Clean up dependencies
    apt-get autoremove -y --purge
    log "INFO" "Prohibited packages removal completed."
}

# =============================================
# SYSTEM HARDENING CONFIGURATIONS
# =============================================

harden_ssh_config() {
    log "INFO" "Hardening SSH configuration..."
    backup_file "/etc/ssh/sshd_config"
    
    # Create secure SSH configuration
    cat > /etc/ssh/sshd_config << 'EOF'
# Core Security Settings
Protocol 2
Port 2200
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2

# Authentication Settings
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# Network Security
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Access Restrictions
AllowUsers
LoginGraceTime 60
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no

# Cryptographic Settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

# Logging
LogLevel VERBOSE
EOF

    # Restart SSH service
    systemctl restart ssh
    log "INFO" "SSH configuration hardened and service restarted."
}

configure_firewall() {
    log "INFO" "Configuring UFW firewall..."
    
    # Reset and enable UFW
    ufw --force reset
    ufw enable
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services (adjust ports as needed)
    ufw allow 2200/tcp comment 'SSH Custom Port'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    log "INFO" "UFW firewall configured with restrictive defaults."
}

harden_sysctl_params() {
    log "INFO" "Configuring kernel security parameters..."
    backup_file "/etc/sysctl.conf"
    
    # Append security settings to sysctl.conf
    cat >> /etc/sysctl.conf << 'EOF'

# ============================================================================
# CyberPatriot Kernel Hardening Parameters
# ============================================================================

# Network Security
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1

# Memory Protections
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
kernel.printk=3 3 3 3

# Filesystem Protections
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

    # Apply settings immediately
    sysctl -p
    log "INFO" "Kernel security parameters configured and applied."
}

# =============================================
# USER ACCOUNT & PASSWORD POLICIES
# =============================================

configure_password_policies() {
    log "INFO" "Configuring comprehensive password policies..."
    
    # Install required PAM module
    apt-get install -y libpam-pwquality
    
    # Configure password policy
    backup_file "/etc/pam.d/common-password"
    cat > /etc/pam.d/common-password << 'EOF'
# CyberPatriot Password Policy
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password requisite pam_pwhistory.so use_authtok remember=5
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
password requisite pam_deny.so
password required pam_permit.so
EOF

    # Configure login.defs
    backup_file "/etc/login.defs"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
    
    # Apply to existing users
    for user in $(getent passwd {1000..60000} | cut -d: -f1); do
        chage -M 90 -m 1 -W 7 "$user"
    done
    
    log "INFO" "Password policies configured and applied to all users."
}

secure_user_accounts() {
    log "INFO" "Securing user accounts..."
    
    # Check for unauthorized UID 0 accounts
    local hidden_roots=$(grep ":0:" /etc/passwd | grep -v "^root:")
    if [[ -n "$hidden_roots" ]]; then
        log "WARNING" "Found hidden UID 0 accounts: $hidden_roots"
        # Comment out unauthorized root accounts
        sed -i 's/^[^#].*:0:/#&/' /etc/passwd
    fi
    
    # Lock system accounts
    for user in $(awk -F: '$3 < 1000 {print $1}' /etc/passwd); do
        if [[ "$user" != "root" ]]; then
            usermod -L "$user" 2>/dev/null || true
        fi
    done
    
    log "INFO" "User account security review completed."
}

# =============================================
# FORENSIC DATA COLLECTION & COMPARATIVE ANALYSIS
# =============================================

collect_forensic_data() {
    log "INFO" "Collecting comprehensive forensic data..."
    
    # Create comparative analysis directory
    mkdir -p "$COMPARATIVE_DIR"
    
    # System information
    create_comparative "system_information" "uname -a && cat /etc/os-release"
    create_comparative "disk_usage" "df -h && mount"
    create_comparative "memory_info" "free -h"
    
    # User and group information
    create_comparative "user_accounts" "getent passwd"
    create_comparative "group_membership" "getent group"
    create_comparative "sudoers_list" "getent group sudo"
    
    # Process and network information
    create_comparative "running_processes" "ps aux"
    create_comparative "network_connections" "netstat -tulnpe"
    create_comparative "listening_ports" "ss -tulnpe"
    
    # Package information
    create_comparative "installed_packages" "dpkg -l"
    create_comparative "services_status" "systemctl list-unit-files --type=service"
    
    # File system analysis
    create_comparative "suid_files" "find / -type f -perm /4000 2>/dev/null"
    create_comparative "world_writable_files" "find / -type f -perm /0002 ! -path '/proc/*' 2>/dev/null"
    create_comparative "recently_modified_files" "find / -type f -mtime -7 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null"
    
    # Security configurations
    create_comparative "firewall_status" "ufw status verbose"
    create_comparative "ssh_config" "cat /etc/ssh/sshd_config"
    
    log "INFO" "Forensic data collection completed. Results saved to $COMPARATIVE_DIR"
}

# =============================================
# MALWARE & INTRUSION DETECTION
# =============================================

install_security_tools() {
    log "INFO" "Installing security monitoring tools..."
    
    # Install essential security tools
    apt-get install -y \
        chkrootkit \
        rkhunter \
        clamav \
        fail2ban \
        auditd \
        lynis
    
    # Update ClamAV definitions
    freshclam
    
    # Configure fail2ban
    systemctl enable fail2ban
    systemctl start fail2ban
    
    log "INFO" "Security tools installed and configured."
}

scan_system() {
    log "INFO" "Performing security scans..."
    
    # Run rkhunter
    rkhunter --update
    rkhunter --check --sk --rwo | tee -a "$LOG_FILE"
    
    # Run chkrootkit
    chkrootkit | tee -a "$LOG_FILE"
    
    # Run Lynis audit
    lynis audit system --quick | tee -a "$LOG_FILE"
    
    log "INFO" "Security scans completed. Check $LOG_FILE for results."
}

# =============================================
# SERVICE HARDENING
# =============================================

harden_common_services() {
    log "INFO" "Hardening common network services..."
    
    # Disable unnecessary services
    local services_to_disable=(
        "bluetooth" "cups" "rpcbind" "nfs-server" "telnet"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl stop "$service"
            systemctl disable "$service"
            log "INFO" "Disabled service: $service"
        fi
    done
    
    # Secure common configuration files
    backup_file "/etc/hosts"
    echo "127.0.0.1 localhost" > /etc/hosts
    echo "::1 localhost ip6-localhost ip6-loopback" >> /etc/hosts
    
    log "INFO" "Common services hardened."
}

# =============================================
# MAIN EXECUTION FUNCTION
# =============================================

main() {
    echo -e "${GREEN}"
    echo "=============================================="
    echo "  CyberPatriot Comprehensive Hardening Script"
    echo "  Version: $SCRIPT_VERSION"
    echo "=============================================="
    echo -e "${NC}"
    
    # Initial checks and setup
    check_root
    mkdir -p "$BACKUP_DIR" "$COMPARATIVE_DIR"
    
    log "INFO" "Script execution started: $SCRIPT_NAME v$SCRIPT_VERSION"
    
    # Execute hardening modules
    configure_automatic_updates
    remove_prohibited_packages
    harden_ssh_config
    configure_firewall
    harden_sysctl_params
    configure_password_policies
    secure_user_accounts
    harden_common_services
    install_security_tools
    
    # Collection and scanning (run last)
    collect_forensic_data
    scan_system
    
    log "INFO" "Script execution completed successfully."
    
    echo -e "${GREEN}"
    echo "=============================================="
    echo "  Hardening Complete - Summary"
    echo "=============================================="
    echo "Log File: $LOG_FILE"
    echo "Backups: $BACKUP_DIR"
    echo "Forensic Data: $COMPARATIVE_DIR"
    echo ""
    echo "Next steps:"
    echo "1. Review the log file for any warnings"
    echo "2. Check forensic data for system baseline"
    echo "3. Test SSH connection on port 2200"
    echo "4. Reboot the system to apply all changes"
    echo -e "${NC}"
}

# =============================================
# SCRIPT EXECUTION
# =============================================

# Execute main function and log all output
main "$@" | tee -a "$LOG_FILE"
