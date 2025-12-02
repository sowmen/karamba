#!/bin/bash

################################################################################
# Multi-User Ubuntu Security Hardening Script
# Purpose: Configure a secure multi-user Ubuntu system with disk quotas
# Usage: sudo ./secure-multiuser-setup.sh
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ADMIN_USER="sysadmin"
SSH_PORT=22
MAX_AUTH_TRIES=5
LOGIN_GRACE_TIME=30

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

if [ "$EUID" -ne 0 ]; then 
    error "Please run as root (use sudo)"
fi

################################################################################
# 1. System Update and Essential Packages
################################################################################

log "Updating system and installing essential packages..."
apt-get update
apt-get upgrade -y
apt-get install -y \
    ufw \
    fail2ban \
    unattended-upgrades \
    quota \
    quotatool \
    apt-listchanges \
    acct \
    libpam-tmpdir \
    aide \
    rkhunter \
    lynis \
    rsyslog \
    logwatch \
    tmux

################################################################################
# 2. Create Admin User
################################################################################

log "Creating administrative user: $ADMIN_USER..."
if ! id "$ADMIN_USER" &>/dev/null; then
    useradd -m -s /bin/bash -G sudo "$ADMIN_USER"
    echo "Please set password for $ADMIN_USER:"
    passwd "$ADMIN_USER"
else
    warn "User $ADMIN_USER already exists, skipping..."
fi

################################################################################
# 3. Configure Disk Quotas
################################################################################

log "Configuring disk quotas..."

if ! grep -q "usrquota,grpquota" /etc/fstab; then
    cp /etc/fstab /etc/fstab.backup
    
    sed -i 's|\(.*\s/\s.*\)\(defaults\)|\1\2,usrquota,grpquota|' /etc/fstab
    
    log "Quotas added to /etc/fstab. Remounting filesystems..."
    mount -o remount /
fi

log "Initializing quota database..."
quotaoff -avug 2>/dev/null || true
quotacheck -cugm /
quotaon -avug

################################################################################
# 4. SSH Hardening
################################################################################
log "Hardening SSH configuration..."

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << EOF
# Secure SSH Configuration
Port $SSH_PORT
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security settings
MaxAuthTries $MAX_AUTH_TRIES
MaxSessions 3
LoginGraceTime ${LOGIN_GRACE_TIME}s
ClientAliveInterval 300
ClientAliveCountMax 2

# Disable insecure features
X11Forwarding no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Override default of no subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Restrict users (uncomment and modify as needed)
# AllowUsers sysadmin user1 user2
# AllowGroups ssh-users

# Banner
Banner /etc/ssh/banner
EOF

cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                    AUTHORIZED ACCESS ONLY
***************************************************************************
Unauthorized access to this system is forbidden and will be prosecuted by law.
By accessing this system, you agree that your actions may be monitored.
***************************************************************************
EOF

################################################################################
# 5. Firewall Configuration (UFW)
################################################################################

log "Configuring firewall..."

ufw --force reset

ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp comment 'SSH'
ufw limit $SSH_PORT/tcp

ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

ufw --force enable

log "Firewall rules applied. SSH is on port $SSH_PORT"

################################################################################
# 6. Fail2ban Configuration
################################################################################

log "Configuring Fail2ban..."

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = $MAX_AUTH_TRIES
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = $MAX_AUTH_TRIES
bantime = 7200
EOF

systemctl enable fail2ban
systemctl restart fail2ban

################################################################################
# 7. Automatic Security Updates
################################################################################

log "Configuring automatic security updates..."

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

################################################################################
# 8. System Security Settings
################################################################################

log "Applying system security settings..."

cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Syn flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore ICMP requests
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

################################################################################
# 9. PAM Security Configuration
################################################################################
log "Configuring PAM security..."

cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
EOF

if ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
    cat >> /etc/pam.d/common-auth << 'EOF'

# Account lockout
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800
EOF
fi

################################################################################
# 10. Audit Logging
################################################################################

log "Configuring audit logging..."

apt-get install -y auditd audispd-plugins

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all previous rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Audit authentication events
-w /var/log/faillog -p wa -k auth
-w /var/log/lastlog -p wa -k auth
-w /var/log/tallylog -p wa -k auth

# Audit user/group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit sudo usage
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Audit SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Make configuration immutable
-e 2
EOF

augenrules --load
systemctl enable auditd
systemctl restart auditd

################################################################################
# 11. File Permission Hardening
################################################################################

log "Hardening file permissions..."

chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /etc/ssh/sshd_config

chmod 750 /home/*/ 2>/dev/null || true

################################################################################
# 12. Disable Unnecessary Services
################################################################################

log "Disabling unnecessary services..."

SERVICES_TO_DISABLE="avahi-daemon cups bluetooth"

for service in $SERVICES_TO_DISABLE; do
    if systemctl list-unit-files | grep -q "$service"; then
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
        log "Disabled $service"
    fi
done

################################################################################
# 13. Create User Management Helper Script
################################################################################

log "Creating user management helper script..."

cat > /usr/local/bin/add-user-with-quota.sh << 'EOFSCRIPT'
#!/bin/bash
# Helper script to add users with disk quotas

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <quota_in_GB>"
    echo "Example: $0 john 10"
    exit 1
fi

USERNAME=$1
QUOTA_GB=$2
QUOTA_BLOCKS=$((QUOTA_GB * 1024 * 1024))  # Convert GB to blocks (1KB blocks)

# Create user
useradd -m -s /bin/bash "$USERNAME"
echo "Set password for $USERNAME:"
passwd "$USERNAME"

# Set disk quota
setquota -u "$USERNAME" $QUOTA_BLOCKS $QUOTA_BLOCKS 0 0 /

# Add to restricted group
groupadd -f users-restricted
usermod -a -G users-restricted "$USERNAME"

# Set home directory permissions
chmod 750 /home/"$USERNAME"

echo "User $USERNAME created with ${QUOTA_GB}GB disk quota"
echo "Current quota:"
quota -vs -u "$USERNAME"
EOFSCRIPT

chmod +x /usr/local/bin/add-user-with-quota.sh

################################################################################
# 14. Setup Log Monitoring
################################################################################

log "Configuring log monitoring..."

# Configure logwatch
cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
Output = mail
Format = html
MailTo = root
MailFrom = logwatch@$(hostname -f)
Range = yesterday
Detail = Med
Service = All
EOF

################################################################################
# 15. Rootkit Detection
################################################################################

log "Configuring rootkit detection..."

rkhunter --update
rkhunter --propupd

cat > /etc/cron.daily/rkhunter << 'EOF'
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet
EOF
chmod +x /etc/cron.daily/rkhunter

################################################################################
# Final Steps
################################################################################

log "Restarting services..."
systemctl restart ssh
systemctl restart rsyslog

################################################################################
# Summary
################################################################################

echo ""
echo "=========================================="
echo "  Security Hardening Complete!"
echo "=========================================="
echo ""
echo "IMPORTANT CHANGES:"
echo "  - SSH port changed to: $SSH_PORT"
echo "  - Root login disabled"
echo "  - Admin user created: $ADMIN_USER"
echo "  - Firewall (UFW) enabled"
echo "  - Fail2ban configured"
echo "  - Disk quotas enabled"
echo "  - Automatic security updates enabled"
echo ""
echo "NEXT STEPS:"
echo "  1. Setup SSH key authentication for $ADMIN_USER"
echo "  2. Disable password authentication in SSH (edit /etc/ssh/sshd_config)"
echo "  3. Create regular users: sudo /usr/local/bin/add-user-with-quota.sh <username> <GB>"
echo "  4. Test SSH connection on port $SSH_PORT before closing this session!"
echo "  5. Configure email for logwatch and fail2ban notifications"
echo ""
echo "SECURITY RECOMMENDATION:"
echo "  After testing SSH access, consider setting PasswordAuthentication to 'no' in /etc/ssh/sshd_config"
echo ""
echo "=========================================="
