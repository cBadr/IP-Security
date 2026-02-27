#!/bin/bash
# firewall.sh - Simplified IP and Country blocking/allowance using iptables + ipset for CentOS
# Requires root privileges.

set -euo pipefail

# ---------- Configuration ----------
IPTABLES="/sbin/iptables"
IPSET="/sbin/ipset"
DOWNLOAD_CMD=""
COUNTRY_URL_PREFIX="https://www.ipdeny.com/ipblocks/data/countries"
IPSET_WHITELIST="whitelist"
IPSET_BLACKLIST="blacklist"
IPSET_COUNTRY_PREFIX="country"
CHAIN_CUSTOM="CUSTOM-FILTER"
CHAIN_ALLOW_COUNTRY="ALLOW-COUNTRY"
CHAIN_BLOCK_COUNTRY="BLOCK-COUNTRY"
SAVE_IPSET="/etc/ipset.conf"
SAVE_IPTABLES="/etc/sysconfig/iptables"

# ---------- Helper Functions ----------
die() {
    echo "❌ Error: $*" >&2
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root."
    fi
}

check_tools() {
    local missing=()
    if ! command -v iptables &>/dev/null; then
        missing+=("iptables")
    fi
    if ! command -v ipset &>/dev/null; then
        missing+=("ipset")
    fi
    if command -v wget &>/dev/null; then
        DOWNLOAD_CMD="wget -qO-"
    elif command -v curl &>/dev/null; then
        DOWNLOAD_CMD="curl -s"
    else
        missing+=("wget or curl")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required tools: ${missing[*]}. Please install them."
    fi
}

init_firewall() {
    # Create ipsets if not exist
    $IPSET list -n | grep -qx "$IPSET_WHITELIST" || $IPSET create $IPSET_WHITELIST hash:net
    $IPSET list -n | grep -qx "$IPSET_BLACKLIST" || $IPSET create $IPSET_BLACKLIST hash:net

    # Create custom chains if not exist
    $IPTABLES -N $CHAIN_CUSTOM 2>/dev/null || true
    $IPTABLES -N $CHAIN_ALLOW_COUNTRY 2>/dev/null || true
    $IPTABLES -N $CHAIN_BLOCK_COUNTRY 2>/dev/null || true

    # Hook custom chain to INPUT if not already
    if ! $IPTABLES -C INPUT -j $CHAIN_CUSTOM &>/dev/null; then
        $IPTABLES -I INPUT -j $CHAIN_CUSTOM
    fi

    # Populate custom chain (order matters)
    # 1. Whitelist: accept
    if ! $IPTABLES -C $CHAIN_CUSTOM -m set --match-set $IPSET_WHITELIST src -j ACCEPT &>/dev/null; then
        $IPTABLES -A $CHAIN_CUSTOM -m set --match-set $IPSET_WHITELIST src -j ACCEPT
    fi
    # 2. Blacklist: drop
    if ! $IPTABLES -C $CHAIN_CUSTOM -m set --match-set $IPSET_BLACKLIST src -j DROP &>/dev/null; then
        $IPTABLES -A $CHAIN_CUSTOM -m set --match-set $IPSET_BLACKLIST src -j DROP
    fi
    # 3. Jump to allow-country chain
    if ! $IPTABLES -C $CHAIN_CUSTOM -j $CHAIN_ALLOW_COUNTRY &>/dev/null; then
        $IPTABLES -A $CHAIN_CUSTOM -j $CHAIN_ALLOW_COUNTRY
    fi
    # 4. Jump to block-country chain
    if ! $IPTABLES -C $CHAIN_CUSTOM -j $CHAIN_BLOCK_COUNTRY &>/dev/null; then
        $IPTABLES -A $CHAIN_CUSTOM -j $CHAIN_BLOCK_COUNTRY
    fi
    # 5. Return to INPUT (default policy applies)
    if ! $IPTABLES -C $CHAIN_CUSTOM -j RETURN &>/dev/null; then
        $IPTABLES -A $CHAIN_CUSTOM -j RETURN
    fi
}

save_config() {
    echo "💾 Saving configuration..."
    $IPSET save > "$SAVE_IPSET"
    $IPTABLES-save > "$SAVE_IPTABLES"
    echo "✅ Saved to $SAVE_IPSET and $SAVE_IPTABLES"
}

validate_ip_or_cidr() {
    local input=$1
    # Simple pattern: numbers, dots, slash
    if [[ ! $input =~ ^[0-9./]+$ ]]; then
        die "Invalid IP/CIDR format: $input"
    fi
}

validate_country_code() {
    local cc=$1
    if [[ ! $cc =~ ^[A-Z]{2}$ ]]; then
        die "Country code must be two uppercase letters (e.g., US, EG). Got: $cc"
    fi
}

add_ip_to_set() {
    local setname=$1
    local ip=$2
    validate_ip_or_cidr "$ip"
    if $IPSET add "$setname" "$ip" 2>/dev/null; then
        echo "✅ Added $ip to $setname"
        save_config
    else
        die "Failed to add $ip to $setname (maybe already exists?)"
    fi
}

remove_ip_from_sets() {
    local ip=$2
    validate_ip_or_cidr "$ip"
    local found=0
    if $IPSET test $IPSET_WHITELIST "$ip" &>/dev/null; then
        $IPSET del $IPSET_WHITELIST "$ip"
        echo "✅ Removed $ip from $IPSET_WHITELIST"
        found=1
    fi
    if $IPSET test $IPSET_BLACKLIST "$ip" &>/dev/null; then
        $IPSET del $IPSET_BLACKLIST "$ip"
        echo "✅ Removed $ip from $IPSET_BLACKLIST"
        found=1
    fi
    if [[ $found -eq 0 ]]; then
        echo "⚠️  IP $ip not found in any list."
    else
        save_config
    fi
}

add_country() {
    local action=$1   # allow or block
    local cc=$2
    validate_country_code "$cc"
    local ipset_name="${IPSET_COUNTRY_PREFIX}-${action}-${cc}"

    # Check if already exists
    if $IPSET list -n | grep -qx "$ipset_name"; then
        die "Country $cc is already ${action}ed (ipset $ipset_name exists). Remove it first if you want to update."
    fi

    # Download country networks
    local url="${COUNTRY_URL_PREFIX}/${cc}.zone"
    echo "🌍 Downloading networks for $cc from $url ..."
    local data
    data=$($DOWNLOAD_CMD "$url") || die "Failed to download country data for $cc (check code or internet)"
    if [[ -z "$data" ]]; then
        die "Empty response for $cc"
    fi

    # Create ipset
    $IPSET create "$ipset_name" hash:net
    local count=0
    echo "➕ Adding networks to ipset $ipset_name ..."
    while IFS= read -r net; do
        if [[ -n "$net" ]]; then
            $IPSET add "$ipset_name" "$net" -exist
            ((count++))
        fi
    done <<< "$data"
    echo "✅ Added $count networks."

    # Determine target chain and jump
    local target_chain
    local jump_target
    if [[ "$action" == "allow" ]]; then
        target_chain="$CHAIN_ALLOW_COUNTRY"
        jump_target="ACCEPT"
    else
        target_chain="$CHAIN_BLOCK_COUNTRY"
        jump_target="DROP"
    fi

    # Add iptables rule with comment
    local comment="${action}-${cc}"
    $IPTABLES -A "$target_chain" -m set --match-set "$ipset_name" src -j "$jump_target" -m comment --comment "$comment"
    echo "✅ Added iptables rule in $target_chain for $cc"

    save_config
}

remove_country() {
    local cc=$2
    validate_country_code "$cc"

    local removed=0
    # Remove from allow chain
    local pattern="$CHAIN_ALLOW_COUNTRY"
    while IFS= read -r rule_num; do
        if [[ -n "$rule_num" ]]; then
            $IPTABLES -D "$pattern" "$rule_num"
            echo "✅ Removed allow rule for $cc"
            removed=1
        fi
    done < <($IPTABLES -L "$pattern" --line-numbers -n | grep "allow-${cc}" | awk '{print $1}' | sort -rn)

    # Remove from block chain
    pattern="$CHAIN_BLOCK_COUNTRY"
    while IFS= read -r rule_num; do
        if [[ -n "$rule_num" ]]; then
            $IPTABLES -D "$pattern" "$rule_num"
            echo "✅ Removed block rule for $cc"
            removed=1
        fi
    done < <($IPTABLES -L "$pattern" --line-numbers -n | grep "block-${cc}" | awk '{print $1}' | sort -rn)

    # Destroy associated ipsets
    for setname in $($IPSET list -n | grep -E "country-(allow|block)-${cc}"); do
        $IPSET destroy "$setname"
        echo "✅ Destroyed ipset $setname"
        removed=1
    done

    if [[ $removed -eq 0 ]]; then
        echo "⚠️  No rules or ipsets found for country $cc."
    else
        save_config
    fi
}

list_allowed() {
    echo "=== 🌟 Allowed IPs (whitelist) ==="
    if $IPSET list $IPSET_WHITELIST &>/dev/null; then
        $IPSET list $IPSET_WHITELIST | sed -n '/Members:/,$p' | tail -n +2 | sed '/^$/d' || echo "(none)"
    else
        echo "(none)"
    fi

    echo -e "\n=== 🌍 Allowed Countries ==="
    $IPTABLES -L $CHAIN_ALLOW_COUNTRY -n -v --line-numbers 2>/dev/null | grep "allow-" | while read -r line; do
        comment=$(echo "$line" | awk '{print $NF}')
        echo "${comment#allow-}"
    done | sort -u || echo "(none)"
}

list_blocked() {
    echo "=== 🔴 Blocked IPs (blacklist) ==="
    if $IPSET list $IPSET_BLACKLIST &>/dev/null; then
        $IPSET list $IPSET_BLACKLIST | sed -n '/Members:/,$p' | tail -n +2 | sed '/^$/d' || echo "(none)"
    else
        echo "(none)"
    fi

    echo -e "\n=== 🌍 Blocked Countries ==="
    $IPTABLES -L $CHAIN_BLOCK_COUNTRY -n -v --line-numbers 2>/dev/null | grep "block-" | while read -r line; do
        comment=$(echo "$line" | awk '{print $NF}')
        echo "${comment#block-}"
    done | sort -u || echo "(none)"
}

list_all() {
    list_allowed
    echo ""
    list_blocked
}

show_help() {
    cat <<EOF
🔒 Firewall Manager for CentOS (iptables + ipset)

Usage: $0 <command> [arguments]

Commands:
  allow ip <IP/CIDR>            Add IP or network to whitelist
  block ip <IP/CIDR>            Add IP or network to blacklist
  remove ip <IP/CIDR>           Remove IP from both whitelist and blacklist

  allow country <CC>            Allow all traffic from country (two-letter code, e.g. US)
  block country <CC>            Block all traffic from country

  remove country <CC>           Remove country from both allow and block lists

  list allowed                  Show allowed IPs and countries
  list blocked                  Show blocked IPs and countries
  list all                      Show both allowed and blocked

  save                          Explicitly save current configuration (autosaved after changes)

Examples:
  $0 allow ip 192.168.1.100
  $0 block ip 10.0.0.0/24
  $0 allow country EG
  $0 block country CN
  $0 remove country US
  $0 list all

Notes:
  - All operations require root.
  - Country lists downloaded from ipdeny.com.
  - Persistent across reboots if you restore ipset/iptables from saved files.
EOF
}

# ---------- Main ----------
check_root
check_tools
init_firewall

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

cmd=$1
case $cmd in
    allow)
        if [[ $# -lt 3 ]]; then
            die "Usage: $0 allow ip <IP/CIDR> or $0 allow country <CC>"
        fi
        type=$2
        value=$3
        if [[ "$type" == "ip" ]]; then
            add_ip_to_set "$IPSET_WHITELIST" "$value"
        elif [[ "$type" == "country" ]]; then
            add_country "allow" "$value"
        else
            die "Unknown type: $type. Use 'ip' or 'country'."
        fi
        ;;
    block)
        if [[ $# -lt 3 ]]; then
            die "Usage: $0 block ip <IP/CIDR> or $0 block country <CC>"
        fi
        type=$2
        value=$3
        if [[ "$type" == "ip" ]]; then
            add_ip_to_set "$IPSET_BLACKLIST" "$value"
        elif [[ "$type" == "country" ]]; then
            add_country "block" "$value"
        else
            die "Unknown type: $type. Use 'ip' or 'country'."
        fi
        ;;
    remove)
        if [[ $# -lt 3 ]]; then
            die "Usage: $0 remove ip <IP/CIDR> or $0 remove country <CC>"
        fi
        type=$2
        value=$3
        if [[ "$type" == "ip" ]]; then
            remove_ip_from_sets "$value"   # note: remove_ip_from_sets expects "$ip" as $2 but we pass $value
        elif [[ "$type" == "country" ]]; then
            remove_country "$value"
        else
            die "Unknown type: $type. Use 'ip' or 'country'."
        fi
        ;;
    list)
        if [[ $# -eq 1 ]]; then
            list_all
        else
            case $2 in
                allowed) list_allowed ;;
                blocked) list_blocked ;;
                all) list_all ;;
                *) die "Unknown list option: $2. Use allowed, blocked, or all." ;;
            esac
        fi
        ;;
    save)
        save_config
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        die "Unknown command: $cmd. See $0 help."
        ;;
esac

exit 0
