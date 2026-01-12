#!/bin/bash

# Script to configure BIND9 to forward queries for epic.aws to AWS Route 53 Resolver
# and setup iptables NAT for DNS traffic to match AWS Network Firewall rules
# Usage: ./setup_bind_forward.sh <resolver-ip-1> [resolver-ip-2]

set -e

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <resolver-ip-1> [resolver-ip-2]"
    echo "Example: $0 10.0.1.251 10.0.0.66"
    exit 1
fi

DOMAIN="epic.aws"
SOURCE_NAT_IP="192.168.100.53"
RESOLVER_IP1=$1
RESOLVER_IP2=${2:-}

NAMED_CONF="/etc/bind/named.conf.local"
BACKUP_DIR="/tmp/bind_backup_$(date +%Y%m%d_%H%M%S)"

echo "Configuring BIND to forward $DOMAIN to AWS Route 53 Resolver..."

# Backup existing config
mkdir -p "$BACKUP_DIR"
if [ -f "$NAMED_CONF" ]; then
    cp "$NAMED_CONF" "$BACKUP_DIR/"
    echo "Backed up existing config to $BACKUP_DIR"
fi

# Create zone configuration
ZONE_CONFIG="
zone \"$DOMAIN\" {
    type forward;
    forward only;
    forwarders {
        $RESOLVER_IP1;"

if [ -n "$RESOLVER_IP2" ]; then
    ZONE_CONFIG="$ZONE_CONFIG
        $RESOLVER_IP2;"
fi

ZONE_CONFIG="$ZONE_CONFIG
    };
};
"

# Add to named.conf.local if not already present
if grep -q "zone \"$DOMAIN\"" "$NAMED_CONF" 2>/dev/null; then
    echo "Warning: Zone $DOMAIN already exists in $NAMED_CONF"
    echo "Skipping configuration. Remove existing zone first if you want to update."
    exit 1
fi

echo "$ZONE_CONFIG" | sudo tee -a "$NAMED_CONF" > /dev/null

# Validate configuration
echo "Validating BIND configuration..."
sudo named-checkconf

# Restart BIND
echo "Restarting BIND9..."
sudo systemctl restart bind9

# Verify service is running
if sudo systemctl is-active --quiet bind9; then
    echo "✓ BIND9 restarted successfully"
else
    echo "✗ BIND9 failed to start. Restoring backup..."
    sudo cp "$BACKUP_DIR/named.conf.local" "$NAMED_CONF"
    sudo systemctl restart bind9
    exit 1
fi

echo ""
echo "Configuration complete!"
echo "Domain: epic.aws"
echo "Forwarders: $RESOLVER_IP1${RESOLVER_IP2:+, $RESOLVER_IP2}"
echo ""

# Setup iptables NAT rules
echo "Setting up iptables NAT rules for DNS traffic..."
echo "Source NAT IP: $SOURCE_NAT_IP"
echo "Destination: 10.0.0.0/8 (AWS VPCs)"

# Check if rules already exist
if sudo iptables -t nat -C POSTROUTING -p udp --dport 53 -d 10.0.0.0/8 -j SNAT --to-source "$SOURCE_NAT_IP" 2>/dev/null; then
    echo "NAT rules already exist, skipping..."
else
    sudo iptables -t nat -A POSTROUTING -p udp --dport 53 -d 10.0.0.0/8 -j SNAT --to-source "$SOURCE_NAT_IP"
    sudo iptables -t nat -A POSTROUTING -p tcp --dport 53 -d 10.0.0.0/8 -j SNAT --to-source "$SOURCE_NAT_IP"
    echo "✓ NAT rules added"
fi

echo ""
echo "Setup complete!"
echo "Test with: dig @localhost test.epic.aws"
echo ""
echo "To make iptables rules persistent across reboots:"
echo "  Ubuntu/Debian: sudo apt install iptables-persistent && sudo netfilter-persistent save"
echo "  RHEL/Amazon Linux: sudo service iptables save"

