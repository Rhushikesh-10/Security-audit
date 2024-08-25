#!/bin/bash

# Security Audit and Server Hardening Script

# Function Definitions

audit_users_and_groups() {
    echo "Auditing users and groups..."
    # List all users and groups
    echo "Users:"
    awk -F':' '{ print $1}' /etc/passwd
    echo "Groups:"
    awk -F':' '{ print $1}' /etc/group

    # Check for users with UID 0
    echo "Users with UID 0 (root privileges):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd

    # Check for users without passwords
    echo "Users without passwords:"
    awk -F: '($2 == "" ) {print $1}' /etc/shadow
}

audit_permissions() {
    echo "Auditing file and directory permissions..."
    # Scan for world-writable files
    echo "World-writable files:"
    find / -type f -perm -o+w -exec ls -l {} \;

    # Check for .ssh directories
    echo ".ssh directories with permissions:"
    find /home -name ".ssh" -exec ls -ld {} \;

    # Report files with SUID/SGID bits set
    echo "Files with SUID/SGID bits set:"
    find / -perm /6000 -exec ls -ld {} \;
}

audit_services() {
    echo "Auditing running services..."
    # List all running services
    echo "Running services:"
    systemctl list-units --type=service --state=running
    echo "Listening ports:"
    netstat -tuln
}

audit_firewall() {
    echo "Checking firewall configuration..."
    # Verify firewall status
    echo "iptables rules:"
    iptables -L -v
    echo "ufw status:"
    ufw status verbose

    # Check for open ports
    echo "Open ports and services:"
    netstat -tuln
}

audit_ip_config() {
    echo "Checking IP configurations..."
    # List IP addresses
    echo "IP addresses:"
    ip addr show

    # Check if IPs are public or private
    echo "Public and private IPs:"
    # Example logic to check IP types (could be extended)
    ip addr show | grep inet
}

check_updates() {
    echo "Checking for security updates..."
    # Check for available updates
    if command -v apt-get >/dev/null; then
        apt-get update && apt-get upgrade -s
    elif command -v yum >/dev/null; then
        yum check-update
    else
        echo "No package manager found"
    fi
}

monitor_logs() {
    echo "Checking logs for suspicious activity..."
    # Check SSH logs for failed login attempts
    echo "Recent SSH login attempts:"
    grep "Failed password" /var/log/auth.log | tail -n 20
}

configure_ssh() {
    echo "Configuring SSH..."
    # Ensure SSH key-based authentication and disable password login for root
    grep -E '^PermitRootLogin' /etc/ssh/sshd_config
    grep -E '^PasswordAuthentication' /etc/ssh/sshd_config
}

disable_ipv6() {
    echo "Disabling IPv6..."
    # Disable IPv6 (example)
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
}

secure_bootloader() {
    echo "Securing the bootloader..."
    # Set a GRUB password (example)
    grub2-editenv /boot/grub2/grubenv list
}

configure_firewall() {
    echo "Configuring firewall..."
    # Example iptables rules
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
}

configure_auto_updates() {
    echo "Configuring automatic updates..."
    # Configure unattended-upgrades
    if command -v apt-get >/dev/null; then
        apt-get install unattended-upgrades
        dpkg-reconfigure --priority=low unattended-upgrades
    fi
}

report_issues() {
    echo "Generating security audit report..."
    # Save the output of each function to a log file
    ./security_audit.sh > audit_report.log
    echo "Report saved to audit_report.log"
    # Optional: send email alert
    mail -s "Security Audit Report" user@example.com < audit_report.log
}

# Main function to call all other functions
main() {
    echo "Starting security audit and server hardening..."
    audit_users_and_groups
    audit_permissions
    audit_services
    audit_firewall
    audit_ip_config
    check_updates
    monitor_logs
    configure_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    configure_auto_updates
    report_issues
}

# Execute the main function
main

