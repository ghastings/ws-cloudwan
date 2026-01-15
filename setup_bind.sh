#!/bin/bash

# Script to setup BIND9 DNS server with local zone and AWS Route 53 forwarding
# Usage: ./setup_bind.sh [resolver-ip-1] [resolver-ip-2]
#        ./setup_bind.sh natonly

set -e

env DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 nginx
systemctl restart networkd-dispatcher.service

# Use static IP address
IP_ADDRESS="192.168.100.53"
DOMAIN="examplecorp.aws"
SOURCE_NAT_IP="192.168.100.53"

echo "Using IP address: $IP_ADDRESS"

# Create zones directory if it doesn't exist
mkdir -p /etc/bind/zones.onprem

# Create zone file
ZONE_FILE="/etc/bind/zones.onprem/db.onprem"
cat > "$ZONE_FILE" << EOF
\$TTL    604800
@       IN      SOA     ns.onprem. admin.onprem. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.onprem.
ns      IN      A       $IP_ADDRESS
www     IN      A       $IP_ADDRESS
EOF

echo "Created zone file: $ZONE_FILE"

# Add zone entry to named.conf.local if not already present
NAMED_CONF="/etc/bind/named.conf.local"
if ! grep -q 'zone "onprem"' "$NAMED_CONF"; then
    cat >> "$NAMED_CONF" << EOF

zone "onprem" {
    type master;
    file "/etc/bind/zones.onprem/db.onprem";
};
EOF
    echo "Added zone entry to $NAMED_CONF"
else
    echo "Zone entry already exists in $NAMED_CONF"
fi

# Check for natonly mode or AWS resolver configuration
if [ "$1" = "natonly" ]; then
    echo ""
    echo "Setting up iptables NAT rules only..."
    
    # Setup iptables NAT rules
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
    echo "NAT setup complete!"
    echo ""
    echo "To make iptables rules persistent across reboots:"
    echo "  Ubuntu/Debian: sudo apt install iptables-persistent && sudo netfilter-persistent save"
    echo "  RHEL/Amazon Linux: sudo service iptables save"
    
    systemctl restart bind9
    echo "BIND service restarted"
    echo "Setup complete. www.onprem now resolves to $IP_ADDRESS"
    exit 0
fi

# Configure AWS Route 53 forwarding if resolver IPs provided
if [ "$#" -ge 1 ]; then
    RESOLVER_IP1=$1
    RESOLVER_IP2=${2:-}
else
    # Use default AWS resolver IPs
    RESOLVER_IP1="10.0.0.66"
    RESOLVER_IP2="10.0.1.66"
fi

NAMED_OPTIONS="/etc/bind/named.conf.options"
BACKUP_DIR="/tmp/bind_backup_$(date +%Y%m%d_%H%M%S)"

echo ""
echo "Configuring BIND to forward $DOMAIN to AWS Route 53 Resolver..."

# Backup existing config
mkdir -p "$BACKUP_DIR"
if [ -f "$NAMED_CONF" ]; then
    cp "$NAMED_CONF" "$BACKUP_DIR/"
    echo "Backed up existing config to $BACKUP_DIR"
fi
if [ -f "$NAMED_OPTIONS" ]; then
    cp "$NAMED_OPTIONS" "$BACKUP_DIR/"
fi

# Disable DNSSEC validation
echo "Disabling DNSSEC validation..."
if grep -q "dnssec-validation" "$NAMED_OPTIONS"; then
    sudo sed -i 's/dnssec-validation .*/dnssec-validation no;/' "$NAMED_OPTIONS"
else
    sudo sed -i '/options {/a \    dnssec-validation no;' "$NAMED_OPTIONS"
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
    echo "Skipping AWS zone configuration."
else
    echo "$ZONE_CONFIG" | sudo tee -a "$NAMED_CONF" > /dev/null
    echo "Added AWS forwarding zone to $NAMED_CONF"
fi

# Validate configuration
echo "Validating BIND configuration..."
sudo named-checkconf

echo ""
echo "AWS forwarding configured!"
echo "Domain: $DOMAIN"
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
echo "Test local zone: dig @localhost www.onprem"
echo "Test AWS zone: dig @localhost test.$DOMAIN"
echo ""
echo "To make iptables rules persistent across reboots:"
echo "  Ubuntu/Debian: sudo apt install iptables-persistent && sudo netfilter-persistent save"
echo "  RHEL/Amazon Linux: sudo service iptables save"

# Restart BIND to apply changes
systemctl restart bind9
echo "BIND service restarted"
echo "Setup complete. www.onprem now resolves to $IP_ADDRESS"
