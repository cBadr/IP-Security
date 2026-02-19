#!/bin/bash
# ============================================================================
# Script: block_world_except_eg_fast.sh
# Description: FAST version - Blocks all world IPs except Egyptian ranges
#              Uses batch processing for lightning speed
# Works with: Firewalld, Iptables, and Fail2ban
# Version: 4.0 (ULTRA FAST)
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
RANGES_FILE="$TEMP_DIR/eg.zone"
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

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root. Use sudo."
        exit 1
    fi
}

validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        return $?
    fi
    return 1
}

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

save_custom_ips() {
    printf "%s\n" "${CUSTOM_IPS[@]}" > "$CUSTOM_IPS_FILE"
    print_success "Saved ${#CUSTOM_IPS[@]} custom IPs to $CUSTOM_IPS_FILE"
}

# FAST function to add IP to all tools
add_ip_to_all() {
    local ip=$1
    
    print_info "Adding IP $ip to all security tools..."
    
    # Add to custom IPs array
    if [[ ! " ${CUSTOM_IPS[@]} " =~ " ${ip} " ]]; then
        CUSTOM_IPS+=("$ip")
    fi
    
    # Add to Firewalld (using batch file)
    echo "rule family='ipv4' source address='$ip' accept" >> "$TEMP_DIR/firewalld_rules.tmp"
    
    # Add to Iptables (using batch file)
    echo "-A INPUT -s $ip -j ACCEPT" >> "$TEMP_DIR/iptables_rules.tmp"
    
    print_success "IP $ip queued for addition"
}

# FAST function to remove IP from all tools
remove_ip_from_all() {
    local ip=$1
    
    print_info "Removing IP $ip from all security tools..."
    
    # Remove from custom IPs array
    CUSTOM_IPS=("${CUSTOM_IPS[@]/$ip}")
    CUSTOM_IPS=($(printf "%s\n" "${CUSTOM_IPS[@]}" | grep -v '^$'))
    
    # Mark for removal in Firewalld (we'll rebuild from scratch)
    touch "$TEMP_DIR/rebuild_needed"
    
    # Remove from Iptables (using batch file for deletion)
    echo "-D INPUT -s $ip -j ACCEPT" >> "$TEMP_DIR/iptables_delete.tmp"
    
    print_success "IP $ip queued for removal"
}

# FAST function to apply all Firewalld changes at once
apply_firewalld_batch() {
    print_info "Applying Firewalld changes in batch mode..."
    
    # Create ipset with all Egyptian ranges at once
    print_info "Creating ipset with Egyptian ranges (this is fast)..."
    firewall-cmd --permanent --delete-ipset="$IPSET_NAME" 2>/dev/null
    firewall-cmd --permanent --new-ipset="$IPSET_NAME" --type=hash:net
    
    # Add all Egyptian ranges in one command using --add-entries-from-file
    if [[ -f "$RANGES_FILE" ]]; then
        firewall-cmd --permanent --ipset="$IPSET_NAME" --add-entries-from-file="$RANGES_FILE"
        print_success "Added all Egyptian ranges to ipset in one operation"
    fi
    
    # Recreate zone
    firewall-cmd --permanent --delete-zone="$FIREWALLD_ZONE" 2>/dev/null
    firewall-cmd --permanent --new-zone="$FIREWALLD_ZONE"
    
    # Add ipset source
    firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-source="ipset:$IPSET_NAME"
    
    # Add default US IP
    firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-rich-rule="rule family='ipv4' source address='$US_IP' accept"
    
    # Add all custom IPs at once (if we have a batch file)
    if [[ -f "$TEMP_DIR/firewalld_rules.tmp" ]]; then
        while IFS= read -r rule; do
            firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-rich-rule="$rule"
        done < "$TEMP_DIR/firewalld_rules.tmp"
    fi
    
    # Add services
    for service in ssh http https; do
        firewall-cmd --permanent --zone="$FIREWALLD_ZONE" --add-service="$service" &>/dev/null
    done
    
    # Set default zone
    firewall-cmd --permanent --set-default-zone=drop
    
    # Reload once
    firewall-cmd --reload
    
    print_success "Firewalld batch update completed"
}

# FAST function to apply all Iptables changes at once
apply_iptables_batch() {
    print_info "Applying Iptables changes in batch mode..."
    
    # Create a temporary rules file
    local RULES_FILE="$TEMP_DIR/iptables_complete.rules"
    
    # Start with fresh rules
    cat > "$RULES_FILE" << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
EOF
    
    # Add default US IP
    echo "-A INPUT -s $US_IP -j ACCEPT" >> "$RULES_FILE"
    
    # Add all Egyptian ranges at once (using grep to format)
    if [[ -f "$RANGES_FILE" ]]; then
        grep -v '^#' "$RANGES_FILE" | grep -v '^$' | sed 's/^/-A INPUT -s /' | sed 's/$/ -j ACCEPT/' >> "$RULES_FILE"
    fi
    
    # Add custom IPs if any
    if [[ -f "$TEMP_DIR/iptables_rules.tmp" ]]; then
        cat "$TEMP_DIR/iptables_rules.tmp" >> "$RULES_FILE"
    fi
    
    # Add COMMIT
    echo "COMMIT" >> "$RULES_FILE"
    
    # Apply all rules at once
    iptables-restore < "$RULES_FILE"
    
    # Handle deletions if needed
    if [[ -f "$TEMP_DIR/iptables_delete.tmp" ]]; then
        while IFS= read -r rule; do
            iptables $rule 2>/dev/null
        done < "$TEMP_DIR/iptables_delete.tmp"
    fi
    
    # Save rules
    if command -v iptables-save &>/dev/null; then
        if [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4
        else
            iptables-save > /etc/sysconfig/iptables
        fi
    fi
    
    print_success "Iptables batch update completed"
}

# FAST function to apply Fail2ban changes
apply_fail2ban_batch() {
    print_info "Applying Fail2ban changes..."
    
    if [[ ! -f "$FAIL2BAN_CONFIG" ]]; then
        cp /etc/fail2ban/jail.conf "$FAIL2BAN_CONFIG" 2>/dev/null || echo "[DEFAULT]" > "$FAIL2BAN_CONFIG"
    fi
    
    # Build ignoreip list (all IPs in one line)
    IGNORE_IPS="$US_IP 127.0.0.1/8 ::1 ${CUSTOM_IPS[*]}"
    
    if grep -q "^ignoreip" "$FAIL2BAN_CONFIG"; then
        sed -i "s/^ignoreip.*/ignoreip = $IGNORE_IPS/" "$FAIL2BAN_CONFIG"
    else
        sed -i "/^\[DEFAULT\]/a ignoreip = $IGNORE_IPS" "$FAIL2BAN_CONFIG"
    fi
    
    systemctl restart fail2ban
    print_success "Fail2ban configuration completed"
}

# ULTRA FAST function to download and process ranges
download_and_process_ranges() {
    print_info "Downloading Egyptian IP ranges..."
    
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR" || exit 1
    
    # Download with progress
    if wget --timeout=10 -q --show-progress "$EG_ZONE_URL" -O eg.zone; then
        print_success "Downloaded Egyptian ranges"
    else
        print_warning "Primary source failed, trying backup..."
        curl -# -s "$BACKUP_URL" -o eg.zone || {
            print_error "Failed to download Egyptian ranges"
            exit 1
        }
    fi
    
    # Count and validate
    RANGE_COUNT=$(wc -l < eg.zone)
    print_success "Downloaded $RANGE_COUNT Egyptian IP ranges"
    
    # Create a clean version (remove comments, empty lines)
    grep -v '^#' eg.zone | grep -v '^$' > eg.zone.clean
    mv eg.zone.clean eg.zone
}

# FAST setup function
fast_setup() {
    print_info "Starting FAST setup..."
    
    # Clear temporary files
    rm -f "$TEMP_DIR"/*.tmp "$TEMP_DIR"/*.rules 2>/dev/null
    
    # Download ranges
    download_and_process_ranges
    
    # Apply configurations in batch mode
    apply_firewalld_batch
    apply_iptables_batch
    apply_fail2ban_batch
    
    # Clean up
    rm -f "$TEMP_DIR"/*.tmp 2>/dev/null
    
    print_success "FAST setup completed in record time!"
}

# Function to show menu
show_menu() {
    clear
    echo "================================================================="
    echo "   Block World Except Egypt - ULTRA FAST Version v4.0"
    echo "================================================================="
    echo ""
    echo "Current Status:"
    echo "  - Egyptian Ranges: $(ipset list $IPSET_NAME 2>/dev/null | grep -c "^[0-9]" 2>/dev/null || echo "Not loaded")"
    echo "  - Custom Whitelisted IPs: ${#CUSTOM_IPS[@]}"
    echo ""
    echo "----------------------- MENU OPTIONS ----------------------------"
    echo -e "${PURPLE}1)${NC} Run FAST setup (block world except Egypt + US IP)"
    echo -e "${PURPLE}2)${NC} Add a new IP to whitelist (queued)"
    echo -e "${PURPLE}3)${NC} Remove an IP from whitelist"
    echo -e "${PURPLE}4)${NC} List all allowed IPs"
    echo -e "${PURPLE}5)${NC} Apply all queued changes"
    echo -e "${PURPLE}6)${NC} Check if an IP is whitelisted"
    echo -e "${PURPLE}7)${NC} Save configuration"
    echo -e "${PURPLE}8)${NC} Exit"
    echo "================================================================="
    echo -n "Please choose an option [1-8]: "
}

# Function to list allowed IPs
list_allowed_ips() {
    echo ""
    echo "==================== ALLOWED IPS SUMMARY ===================="
    
    echo -e "\n${GREEN}Egyptian Ranges:${NC}"
    if command -v ipset &>/dev/null; then
        local eg_count=$(ipset list $IPSET_NAME 2>/dev/null | grep -c "^[0-9]" 2>/dev/null)
        echo "  - Total ranges: $eg_count"
        echo "  - Sample (first 5):"
        ipset list $IPSET_NAME 2>/dev/null | grep "^[0-9]" | head -5 | sed 's/^/    /'
    fi
    
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
    
    echo -e "\n${YELLOW}Queued changes:${NC}"
    if [[ -f "$TEMP_DIR/firewalld_rules.tmp" ]]; then
        echo "  - $(wc -l < "$TEMP_DIR/firewalld_rules.tmp") IPs waiting to be added"
    fi
    if [[ -f "$TEMP_DIR/iptables_delete.tmp" ]]; then
        echo "  - $(wc -l < "$TEMP_DIR/iptables_delete.tmp") IPs waiting to be removed"
    fi
    
    echo "================================================================"
}

# Function to apply all queued changes
apply_queued_changes() {
    print_info "Applying all queued changes..."
    
    # Check if there are changes to apply
    if [[ ! -f "$TEMP_DIR/firewalld_rules.tmp" && ! -f "$TEMP_DIR/iptables_delete.tmp" ]]; then
        print_warning "No queued changes to apply"
        return
    fi
    
    # Apply firewalld changes
    if [[ -f "$TEMP_DIR/firewalld_rules.tmp" ]] || [[ -f "$TEMP_DIR/rebuild_needed" ]]; then
        apply_firewalld_batch
    fi
    
    # Apply iptables changes
    if [[ -f "$TEMP_DIR/iptables_rules.tmp" ]] || [[ -f "$TEMP_DIR/iptables_delete.tmp" ]]; then
        apply_iptables_batch
    fi
    
    # Update fail2ban
    apply_fail2ban_batch
    
    # Clean up temp files
    rm -f "$TEMP_DIR"/*.tmp 2>/dev/null
    
    print_success "All queued changes applied"
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
    
    # Check if it's within Egyptian ranges
    if ipset test $IPSET_NAME "$ip" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} This IP falls within Egyptian ranges"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# ---------------------------- Main Execution -----------------------------
main() {
    check_root
    touch "$LOG_FILE"
    mkdir -p "$TEMP_DIR"
    load_custom_ips
    
    while true; do
        show_menu
        read choice
        
        case $choice in
            1)
                fast_setup
                read -p "Press Enter to continue..."
                ;;
            2)
                echo ""
                read -p "Enter IP address to whitelist: " new_ip
                if validate_ip "$new_ip"; then
                    add_ip_to_all "$new_ip"
                    print_info "IP queued. Use option 5 to apply changes."
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
                        print_info "IP queued for removal. Use option 5 to apply changes."
                    elif validate_ip "$remove_input"; then
                        remove_ip_from_all "$remove_input"
                        print_info "IP queued for removal. Use option 5 to apply changes."
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
                apply_queued_changes
                read -p "Press Enter to continue..."
                ;;
            6)
                check_ip_whitelisted
                ;;
            7)
                save_custom_ips
                print_success "Configuration saved"
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
