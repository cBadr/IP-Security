#!/bin/bash
# ============================================================================
# Script: block_world_except_eg_v2.sh
# Description: Blocks all world IPs except Egyptian ranges and allows
#              adding custom IPs to whitelist across all security tools
# Works with: Firewalld, Iptables, and Fail2ban
# Version: 3.0 (with IP management)
# ============================================================================

# ---------------------------- Configuration ---------------------------------
US_IP="65.75.201.81"                    # Default US IP to allow
EG_ZONE_URL="https://www.ipdeny.com/ipblocks/data/countries/eg.zone"
BACKUP_URL="https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/eg.cidr"
IPSET_NAME="egypt_whitelist"
FIREWALLD_ZONE="egypt_allowed"
FAIL2BAN_CONFIG="/etc/fail2ban/jail.local"
CUSTOM_IPS_FILE="/etc/whitelist_custom_ips.conf"
TEMP_DIR="/tmp/eg_ip_rules"
LOG_FILE="/var/log/block_world_except_eg.log"
# ----------------------------------------------------------------------------

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# ---------------------------- Functions -------------------------------------
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "[SUCCESS] $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_message "[INFO] $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log_message "[WARNING] $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log_message "[ERROR] $1"
}

print_menu_option() {
    echo -e "${PURPLE}[MENU]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use sudo."
        exit 1
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Function to load custom IPs from file
load_custom_ips() {
    if [[ -f "$CUSTOM_IPS_FILE" ]]; then
        mapfile -t CUSTOM_IPS < "$CUSTOM_IPS_FILE"
        print_info "Loaded ${#CUSTOM_IPS[@]} custom IPs from $CUSTOM_IPS_FILE"
    else
        CUSTOM_IPS=()
        touch "$CUSTOM_IPS_FILE"
        print_info "Created new custom IPs file: $CUSTOM_IPS_FILE"
    fi
}

# Function to save custom IPs to file
save_custom_ips() {
    printf "%s\n" "${CUSTOM_IPS[@]}" > "$CUSTOM_IPS_FILE"
    print_success "Saved ${#CUSTOM_IPS[@]} custom IPs to $CUSTOM_IPS_FILE"
}

# Function to add IP to all security tools
add_ip_to_all() {
    local ip=$1
    local description=${2:-"Custom whitelisted IP"}
    
    print_info "Adding IP $ip to all security tools..."
    
    # Add to custom IPs array if not already present
    if [[ ! " ${CUSTOM_IPS[@]} " =~ " ${ip} " ]]; then
        CUSTOM_IPS+=("$ip")
        print_success "Added $ip to custom IPs list"
    else
        print_warning "IP $ip already in custom IPs list"
    fi
    
    # Add to Firewalld
    if systemctl is-active --quiet firewalld; then
        # Add to the egypt_allowed zone
        firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-rich-rule="rule family='ipv4' source address='$ip' accept"
        firewall-cmd --reload
        print_success "Added $ip to Firewalld zone $FIREWALLD_ZONE"
    fi
    
    # Add to Iptables
    if command -v iptables &>/dev/null; then
        # Check if rule already exists
        if ! iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -s "$ip" -j ACCEPT
            # Save iptables rules
            if command -v iptables-save &>/dev/null; then
                if [[ -d /etc/iptables ]]; then
                    iptables-save > /etc/iptables/rules.v4
                else
                    iptables-save > /etc/sysconfig/iptables
                fi
            fi
            print_success "Added $ip to Iptables"
        else
            print_warning "IP $ip already exists in Iptables"
        fi
    fi
    
    # Add to Fail2ban ignoreip
    if systemctl is-active --quiet fail2ban && [[ -f "$FAIL2BAN_CONFIG" ]]; then
        # Get current ignoreip
        CURRENT_IGNORE=$(grep "^ignoreip" "$FAIL2BAN_CONFIG" | cut -d'=' -f2- | sed 's/^[ \t]*//')
        
        # Check if IP already in ignoreip
        if [[ ! "$CURRENT_IGNORE" =~ "$ip" ]]; then
            NEW_IGNORE="$CURRENT_IGNORE $ip"
            sed -i "s/^ignoreip.*/ignoreip = $NEW_IGNORE/" "$FAIL2BAN_CONFIG"
            systemctl restart fail2ban
            print_success "Added $ip to Fail2ban ignoreip"
        else
            print_warning "IP $ip already in Fail2ban ignoreip"
        fi
    fi
    
    save_custom_ips
    print_success "IP $ip has been added to all security tools"
}

# Function to remove IP from all security tools
remove_ip_from_all() {
    local ip=$1
    
    print_info "Removing IP $ip from all security tools..."
    
    # Remove from custom IPs array
    CUSTOM_IPS=("${CUSTOM_IPS[@]/$ip}")
    # Remove empty elements
    CUSTOM_IPS=($(printf "%s\n" "${CUSTOM_IPS[@]}" | grep -v '^$'))
    
    # Remove from Firewalld
    if systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --remove-rich-rule="rule family='ipv4' source address='$ip' accept"
        firewall-cmd --reload
        print_success "Removed $ip from Firewalld zone $FIREWALLD_ZONE"
    fi
    
    # Remove from Iptables
    if command -v iptables &>/dev/null; then
        iptables -D INPUT -s "$ip" -j ACCEPT 2>/dev/null
        # Save iptables rules
        if command -v iptables-save &>/dev/null; then
            if [[ -d /etc/iptables ]]; then
                iptables-save > /etc/iptables/rules.v4
            else
                iptables-save > /etc/sysconfig/iptables
            fi
        fi
        print_success "Removed $ip from Iptables"
    fi
    
    # Remove from Fail2ban ignoreip
    if systemctl is-active --quiet fail2ban && [[ -f "$FAIL2BAN_CONFIG" ]]; then
        # Get current ignoreip
        CURRENT_IGNORE=$(grep "^ignoreip" "$FAIL2BAN_CONFIG" | cut -d'=' -f2-)
        # Remove the IP
        NEW_IGNORE=$(echo "$CURRENT_IGNORE" | sed "s/\b$ip\b//g" | tr -s ' ')
        sed -i "s/^ignoreip.*/ignoreip = $NEW_IGNORE/" "$FAIL2BAN_CONFIG"
        systemctl restart fail2ban
        print_success "Removed $ip from Fail2ban ignoreip"
    fi
    
    save_custom_ips
    print_success "IP $ip has been removed from all security tools"
}

# Function to list all allowed IPs
list_allowed_ips() {
    echo ""
    echo "==================== ALLOWED IPS SUMMARY ===================="
    echo -e "${GREEN}Egyptian Ranges:${NC} (Loaded from ipset)"
    echo "  - Total ranges: $(ipset list $IPSET_NAME 2>/dev/null | grep -c "^[0-9]" 2>/dev/null || echo "N/A")"
    
    echo -e "\n${GREEN}Default US IP:${NC}"
    echo "  - $US_IP"
    
    echo -e "\n${GREEN}Custom Whitelisted IPs:${NC}"
    if [[ ${#CUSTOM_IPS[@]} -gt 0 ]]; then
        for ip in "${CUSTOM_IPS[@]}"; do
            echo "  - $ip"
        done
    else
        echo "  - No custom IPs added"
    fi
    
    echo -e "\n${BLUE}Firewalld Zone '$FIREWALLD_ZONE' rules:${NC}"
    firewall-cmd --zone="$FIREWALLD_ZONE" --list-rich-rules 2>/dev/null | sed 's/^/  /'
    
    echo "================================================================"
}

# Function to check requirements
check_requirements() {
    print_info "Checking and installing requirements..."
    
    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt-get"
        PKG_UPDATE="$PKG_MANAGER update -qq"
        PKG_INSTALL="$PKG_MANAGER install -y -qq"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        PKG_UPDATE="$PKG_MANAGER check-update"
        PKG_INSTALL="$PKG_MANAGER install -y -q"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        PKG_UPDATE="$PKG_MANAGER check-update"
        PKG_INSTALL="$PKG_MANAGER install -y -q"
    else
        print_error "Could not detect package manager"
        exit 1
    fi
    
    # Install required packages
    REQUIRED_PKGS=("wget" "curl" "ipset" "iptables" "firewalld" "fail2ban")
    
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! command -v $pkg &>/dev/null && ! rpm -q $pkg &>/dev/null 2>&1 && ! dpkg -l $pkg &>/dev/null 2>&1; then
            print_info "Installing: $pkg"
            $PKG_INSTALL $pkg || print_warning "Failed to install $pkg"
        fi
    done
    
    # Start and enable services
    for service in firewalld fail2ban; do
        if systemctl list-unit-files | grep -q "$service"; then
            systemctl enable --now $service &>/dev/null
        fi
    done
}

# Function to download Egyptian ranges
download_egyptian_ranges() {
    print_info "Downloading Egyptian IP ranges..."
    
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR" || exit 1
    
    if wget --timeout=10 -q "$EG_ZONE_URL" -O eg.zone; then
        print_success "Downloaded Egyptian ranges"
    else
        print_warning "Primary source failed, trying backup..."
        curl -s "$BACKUP_URL" -o eg.zone || {
            print_error "Failed to download Egyptian ranges"
            exit 1
        }
    fi
    
    RANGE_COUNT=$(wc -l < eg.zone)
    print_success "Downloaded $RANGE_COUNT Egyptian IP ranges"
}

# Function to setup firewalld
setup_firewalld() {
    print_info "Configuring Firewalld..."
    
    firewall-cmd --permanent --delete-ipset="$IPSET_NAME" 2>/dev/null
    firewall-cmd --permanent --delete-zone="$FIREWALLD_ZONE" 2>/dev/null
    
    firewall-cmd --permanent --new-ipset="$IPSET_NAME" --type=hash:net
    
    # Add Egyptian ranges
    while IFS= read -r range; do
        [[ -n "$range" ]] && firewall-cmd --permanent --ipset="$IPSET_NAME" --add-entry="$range"
    done < eg.zone
    
    # Create zone and add sources
    firewall-cmd --permanent --new-zone="$FIREWALLD_ZONE"
    firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-source="ipset:$IPSET_NAME"
    
    # Add default US IP
    firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-rich-rule="rule family='ipv4' source address='$US_IP' accept"
    
    # Add custom IPs
    for ip in "${CUSTOM_IPS[@]}"; do
        firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-rich-rule="rule family='ipv4' source address='$ip' accept"
    done
    
    # Allow services
    for service in ssh http https; do
        firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-service="$service" &>/dev/null
    done
    
    firewall-cmd --permanent --set-default-zone=drop
    firewall-cmd --reload
    
    print_success "Firewalld configuration completed"
}

# Function to setup iptables
setup_iptables() {
    print_info "Configuring Iptables..."
    
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    
    # Add default US IP
    iptables -A INPUT -s "$US_IP" -j ACCEPT
    
    # Add custom IPs
    for ip in "${CUSTOM_IPS[@]}"; do
        iptables -A INPUT -s "$ip" -j ACCEPT
    done
    
    # Add Egyptian ranges
    while IFS= read -r range; do
        [[ -n "$range" ]] && iptables -A INPUT -s "$range" -j ACCEPT
    done < eg.zone
    
    # Save rules
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4
        else
            iptables-save > /etc/sysconfig/iptables
        fi
    fi
    
    print_success "Iptables configuration completed"
}

# Function to setup fail2ban
setup_fail2ban() {
    print_info "Configuring Fail2ban..."
    
    if [[ ! -f "$FAIL2BAN_CONFIG" ]]; then
        cp /etc/fail2ban/jail.conf "$FAIL2BAN_CONFIG" 2>/dev/null || echo "[DEFAULT]" > "$FAIL2BAN_CONFIG"
    fi
    
    # Build ignoreip list
    IGNORE_IPS="$US_IP 127.0.0.1/8 ::1 ${CUSTOM_IPS[*]}"
    
    if grep -q "^ignoreip" "$FAIL2BAN_CONFIG"; then
        sed -i "s/^ignoreip.*/ignoreip = $IGNORE_IPS/" "$FAIL2BAN_CONFIG"
    else
        sed -i "/^\[DEFAULT\]/a ignoreip = $IGNORE_IPS" "$FAIL2BAN_CONFIG"
    fi
    
    systemctl restart fail2ban
    print_success "Fail2ban configuration completed"
}

# Function to show main menu
show_menu() {
    clear
    echo "================================================================="
    echo "     Block World Except Egypt - IP Management Script v3.0"
    echo "================================================================="
    echo ""
    echo "Current Status:"
    echo "  - Egyptian Ranges: $(ipset list $IPSET_NAME 2>/dev/null | grep -c "^[0-9]" 2>/dev/null || echo "Not loaded")"
    echo "  - Custom Whitelisted IPs: ${#CUSTOM_IPS[@]}"
    echo "  - Default US IP: $US_IP"
    echo ""
    echo "----------------------- MENU OPTIONS ----------------------------"
    print_menu_option "1) Run full setup (block world except Egypt + US IP)"
    print_menu_option "2) Add a new IP to whitelist (all tools)"
    print_menu_option "3) Remove an IP from whitelist"
    print_menu_option "4) List all allowed IPs"
    print_menu_option "5) Check if an IP is whitelisted"
    print_menu_option "6) Save current configuration"
    print_menu_option "7) Restore default configuration (US IP only)"
    print_menu_option "8) Exit"
    echo "================================================================="
    echo -n "Please choose an option [1-8]: "
}

# Function to check if IP is whitelisted
check_ip_whitelisted() {
    read -p "Enter IP address to check: " ip
    
    if ! validate_ip "$ip"; then
        print_error "Invalid IP address format"
        return
    fi
    
    echo ""
    echo "Checking IP $ip in all tools..."
    
    # Check in custom list
    if [[ " ${CUSTOM_IPS[@]} " =~ " ${ip} " ]]; then
        echo -e "${GREEN}✓${NC} Found in custom whitelist"
    else
        echo -e "${RED}✗${NC} Not in custom whitelist"
    fi
    
    # Check in firewalld
    if firewall-cmd --zone="$FIREWALLD_ZONE" --query-rich-rule="rule family='ipv4' source address='$ip' accept" &>/dev/null; then
        echo -e "${GREEN}✓${NC} Found in Firewalld"
    else
        echo -e "${RED}✗${NC} Not in Firewalld"
    fi
    
    # Check in iptables
    if iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Found in Iptables"
    else
        echo -e "${RED}✗${NC} Not in Iptables"
    fi
    
    # Check in fail2ban
    if grep -q "^ignoreip.*$ip" "$FAIL2BAN_CONFIG" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Found in Fail2ban ignoreip"
    else
        echo -e "${RED}✗${NC} Not in Fail2ban ignoreip"
    fi
    
    # Check if it's the default US IP
    if [[ "$ip" == "$US_IP" ]]; then
        echo -e "${GREEN}✓${NC} This is the default US IP"
    fi
    
    # Check if it's within Egyptian ranges (basic check)
    if ipset test $IPSET_NAME "$ip" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} This IP falls within Egyptian ranges"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Function to restore default configuration
restore_default() {
    print_warning "This will remove all custom IPs and restore to default (US IP only)"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        CUSTOM_IPS=()
        save_custom_ips
        
        # Re-run setup without custom IPs
        download_egyptian_ranges
        setup_firewalld
        setup_iptables
        setup_fail2ban
        
        print_success "Restored to default configuration"
    else
        print_info "Operation cancelled"
    fi
}

# ---------------------------- Main Execution -----------------------------
main() {
    check_root
    touch "$LOG_FILE"
    load_custom_ips
    
    while true; do
        show_menu
        read choice
        
        case $choice in
            1)
                print_info "Starting full setup..."
                check_requirements
                download_egyptian_ranges
                setup_firewalld
                setup_iptables
                setup_fail2ban
                print_success "Full setup completed"
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                read -p "Enter IP address to whitelist: " new_ip
                if validate_ip "$new_ip"; then
                    read -p "Enter description (optional): " description
                    add_ip_to_all "$new_ip" "$description"
                else
                    print_error "Invalid IP address format"
                fi
                read -p "Press Enter to continue..."
                ;;
            3)
                echo ""
                if [[ ${#CUSTOM_IPS[@]} -eq 0 ]]; then
                    print_warning "No custom IPs to remove"
                else
                    echo "Custom whitelisted IPs:"
                    for i in "${!CUSTOM_IPS[@]}"; do
                        echo "  $((i+1))) ${CUSTOM_IPS[$i]}"
                    done
                    echo ""
                    read -p "Enter IP address to remove (or number): " remove_input
                    
                    if [[ "$remove_input" =~ ^[0-9]+$ ]] && [ "$remove_input" -le "${#CUSTOM_IPS[@]}" ]; then
                        ip_to_remove="${CUSTOM_IPS[$((remove_input-1))]}"
                        remove_ip_from_all "$ip_to_remove"
                    elif validate_ip "$remove_input"; then
                        remove_ip_from_all "$remove_input"
                    else
                        print_error "Invalid input"
                    fi
                fi
                read -p "Press Enter to continue..."
                ;;
            4)
                list_allowed_ips
                read -p "Press Enter to continue..."
                ;;
            5)
                check_ip_whitelisted
                ;;
            6)
                save_custom_ips
                print_success "Configuration saved"
                read -p "Press Enter to continue..."
                ;;
            7)
                restore_default
                read -p "Press Enter to continue..."
                ;;
            8)
                print_info "Exiting script"
                rm -rf "$TEMP_DIR"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1-8"
                sleep 2
                ;;
        esac
    done
}

# Trap for cleanup
trap 'rm -rf "$TEMP_DIR"; print_info "Script terminated"; exit' INT TERM

# Run main function
main
