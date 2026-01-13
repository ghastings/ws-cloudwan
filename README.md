# CloudWAN Workshop Scripts

Scripts for deploying and configuring AWS Cloud WAN with DNS forwarding.

## Scripts

### deploy_cloudwan.py

Python script that automates Cloud WAN deployment and configuration:
- Deploys Cloud WAN core network policies
- Configures VPC route tables for inspection traffic flow
- Updates routing to direct traffic through Network Firewall inspection VPCs
- Supports multi-region deployments (eu-north-1, us-west-2)

**Usage:**
```bash
python deploy_cloudwan.py
```

### setup_bind.sh

Complete BIND9 DNS server setup for on-premises simulation:
- Installs and configures BIND9 and nginx
- Creates local `.onprem` zone (www.onprem → 192.168.100.53)
- Configures forwarding for `epic.aws` domain to AWS Route 53 resolvers
- Disables DNSSEC validation for AWS forwarding
- Sets up iptables NAT rules to source DNS traffic from 192.168.100.53
- Defaults to resolver IPs: 10.0.0.66 and 10.0.1.66

**Usage:**
```bash
# Use default resolver IPs (10.0.0.66, 10.0.1.66)
./setup_bind.sh

# Specify custom resolver IPs
./setup_bind.sh 10.0.0.66 10.0.1.251

# Configure NAT rules only
./setup_bind.sh natonly
```

### setup_bind_forward.sh

Standalone script for configuring AWS Route 53 forwarding on existing BIND installations:
- Adds `epic.aws` forwarding zone
- Disables DNSSEC validation
- Configures iptables NAT rules
- Defaults to resolver IPs: 10.0.0.66 and 10.0.1.66

**Usage:**
```bash
# Use default resolver IPs
./setup_bind_forward.sh

# Specify custom resolver IPs
./setup_bind_forward.sh 10.0.0.66 10.0.1.66

# Configure NAT rules only
./setup_bind_forward.sh natonly
```

## Authentication

### AWS Credentials Setup

Copy your workshop credentials directly into a `secret.env` file:

```bash
# Create secret.env with your workshop credentials
cat > secret.env << 'EOF'
export AWS_DEFAULT_REGION="eu-north-1"
export AWS_ACCESS_KEY_ID="xxxxx"
export AWS_SECRET_ACCESS_KEY="xxxxxx"
export AWS_SESSION_TOKEN="xxxxxx..."
EOF

# Load credentials
source secret.env
```

**Note:** The `secret.env` file is gitignored and will not be committed to the repository.

## Testing

### Test Local DNS
```bash
dig @localhost www.onprem
```

### Test AWS DNS Forwarding
```bash
dig @localhost test.epic.aws
```

### Verify NAT Rules
```bash
sudo iptables -t nat -L POSTROUTING -n -v
```