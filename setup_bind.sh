#!/bin/bash

env DEBIAN_FRONTEND=noninteractive apt-get install -y bind9 nginx
systemctl restart networkd-dispatcher.service

# Use static IP address
IP_ADDRESS="192.168.100.53"

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

# Restart BIND to apply changes
systemctl restart bind9
echo "BIND service restarted"
echo "Setup complete. www.onprem now resolves to $IP_ADDRESS"
