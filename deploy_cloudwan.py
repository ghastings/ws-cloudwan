#!/usr/bin/env python3
"""
CloudWAN Deployment Script
Multi-step deployment for CloudWAN infrastructure
"""

import boto3
import json
import argparse
import sys
import time
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Region mapping
REGION_MAP = {
    "stockholm": "eu-north-1",
    "oregon": "us-west-2"
}

# Route table configurations (same for both regions)
ROUTE_CONFIGS = [
    {"vpc_name": "prod-vpc-*", "route_table_name": "*Private*", "destination": "0.0.0.0/0"},
    {"vpc_name": "thirdparty-vpc-*", "route_table_name": "*Private*", "destination": "0.0.0.0/0"},
    {"vpc_name": "eastwest-inspection-vpc-*", "route_table_name": "*Firewall*", "destination": "0.0.0.0/0"},
    {"vpc_name": "egress-inspection-vpc-*", "route_table_name": "*Firewall*", "destination": "10.0.0.0/8"},
]


@dataclass
class AttachmentConfig:
    name: str
    edge_location: str
    appliance_mode: bool
    vpc_id: str
    tag_key: str
    tag_value: str


@dataclass
class VPNAttachmentConfig:
    name: str
    edge_location: str
    tag_key: str
    tag_value: str


def get_account_id(session) -> str:
    """Get AWS account ID from STS"""
    sts = session.client('sts')
    return sts.get_caller_identity()['Account']


def get_network_policy(step: str = "initial") -> Dict[str, Any]:
    """Load the CloudWAN network policy from JSON file"""
    filename = 'step2-cnp.json' if step == "initial" else 'step5-routing-cnp.json'
    
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filename} file not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing {filename}: {e}")
        sys.exit(1)


def deploy_network_policy(nm_client, core_network_id: str, step: str = "initial") -> Dict[str, Any]:
    """Deploy the network policy to CloudWAN core network"""
    policy = get_network_policy(step)
    description = "CloudWAN network policy with segments and NFGs" if step == "initial" else "CloudWAN routing policy with segment actions"
    
    try:
        print(f"Deploying {step} network policy...")
        policy_json = json.dumps(policy)
        response = nm_client.put_core_network_policy(
            CoreNetworkId=core_network_id,
            PolicyDocument=policy_json,
            Description=description
        )
        
        policy_version_id = response['CoreNetworkPolicy']['PolicyVersionId']
        print(f"✓ Policy created with version ID: {policy_version_id}")
        
        # Wait for policy generation to complete
        print("Waiting for policy generation to complete...")
        if not wait_for_policy_generation(nm_client, core_network_id, policy_version_id):
            return {'status': 'failed', 'error': 'Policy generation failed or timed out'}
        
        print("Executing policy...")
        execute_response = nm_client.execute_core_network_change_set(
            CoreNetworkId=core_network_id,
            PolicyVersionId=policy_version_id
        )
        
        print("✓ Policy execution initiated")
        print("Waiting for policy execution to complete...")
        wait_for_policy_execution(nm_client, core_network_id)
        
        return {
            'status': 'success',
            'policy_version_id': policy_version_id,
            'execution_response': execute_response
        }
        
    except Exception as e:
        error_msg = str(e)
        print(f"Error deploying network policy: {error_msg}")
        # Try to get more details from the exception
        if hasattr(e, 'response'):
            error_details = e.response.get('Error', {})
            if 'Message' in error_details:
                print(f"Details: {error_details['Message']}")
        return {'status': 'failed', 'error': error_msg}


def wait_for_attachments_available(nm_client, core_network_id: str, max_wait: int = 1200):
    """Wait for all attachments to be in AVAILABLE state, accepting pending ones"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = nm_client.list_attachments(CoreNetworkId=core_network_id)
            attachments = response.get('Attachments', [])
            
            if not attachments:
                print("No attachments found")
                return True
            
            # Accept any pending attachments
            pending_acceptance = [a for a in attachments if a['State'] == 'PENDING_ATTACHMENT_ACCEPTANCE']
            for att in pending_acceptance:
                att_id = att['AttachmentId']
                print(f"  Accepting attachment: {att_id}")
                try:
                    nm_client.accept_attachment(AttachmentId=att_id)
                except Exception as e:
                    print(f"  Warning: Could not accept {att_id}: {e}")
            
            creating = [a for a in attachments if a['State'] in ['CREATING', 'PENDING_ATTACHMENT_ACCEPTANCE', 'PENDING_NETWORK_UPDATE']]
            available = [a for a in attachments if a['State'] == 'AVAILABLE']
            failed = [a for a in attachments if a['State'] in ['FAILED', 'REJECTED']]
            
            if failed:
                print(f"✗ {len(failed)} attachment(s) failed")
                for att in failed:
                    print(f"  {att.get('AttachmentId')}: {att['State']}")
                return False
            
            if creating:
                print(f"Waiting for {len(creating)} attachment(s) to be available... ({len(available)}/{len(attachments)} ready)")
                time.sleep(30)
            else:
                print(f"✓ All {len(attachments)} attachments are available")
                return True
                
        except Exception as e:
            print(f"Error checking attachment status: {e}")
            time.sleep(30)
    
    print("Timeout waiting for attachments")
    return False


def wait_for_policy_generation(nm_client, core_network_id: str, policy_version_id: int, max_wait: int = 300):
    """Wait for policy generation to complete before executing"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = nm_client.get_core_network_policy(
                CoreNetworkId=core_network_id,
                PolicyVersionId=policy_version_id
            )
            state = response['CoreNetworkPolicy']['ChangeSetState']
            
            if state == 'READY_TO_EXECUTE':
                print("✓ Policy generation completed")
                return True
            elif state == 'PENDING_GENERATION':
                print(f"Policy generation in progress... (state: {state})")
                time.sleep(10)
            elif state == 'FAILED_GENERATION':
                print(f"Policy generation failed")
                return False
            else:
                print(f"Policy state: {state}")
                time.sleep(10)
                
        except Exception as e:
            print(f"Error checking policy generation status: {e}")
            time.sleep(10)
    
    print("Timeout waiting for policy generation")
    return False


def wait_for_policy_execution(nm_client, core_network_id: str, max_wait: int = 600):
    """Wait for policy execution to complete"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = nm_client.get_core_network(CoreNetworkId=core_network_id)
            state = response['CoreNetwork']['State']
            
            if state == 'AVAILABLE':
                print("✓ Policy execution completed successfully")
                return True
            elif state in ['CREATING', 'UPDATING']:
                print(f"Policy execution in progress... (state: {state})")
                time.sleep(30)
            else:
                print(f"Unexpected state: {state}")
                return False
                
        except Exception as e:
            print(f"Error checking policy status: {e}")
            time.sleep(30)
    
    print("Timeout waiting for policy execution")
    return False


def get_onprem_instance_ip(ec2_client) -> Optional[str]:
    """Get the public IP of the onprem EC2 instance"""
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': ['onprem']},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if public_ip := instance.get('PublicIpAddress'):
                    return public_ip
        return None
    except Exception as e:
        print(f"Error getting onprem instance IP: {e}")
        return None


def create_site_to_site_vpn(ec2_client, onprem_ip: str) -> Dict[str, Any]:
    """Create Site-to-Site VPN connection"""
    try:
        print(f"Creating Site-to-Site VPN with onprem IP: {onprem_ip}")
        
        cgw_response = ec2_client.create_customer_gateway(
            BgpAsn=64512,
            PublicIp=onprem_ip,
            Type='ipsec.1',
            TagSpecifications=[{
                'ResourceType': 'customer-gateway',
                'Tags': [{'Key': 'Name', 'Value': 'onpremises-cgw'}]
            }]
        )
        
        customer_gateway_id = cgw_response['CustomerGateway']['CustomerGatewayId']
        print(f"✓ Created customer gateway: {customer_gateway_id}")
        
        vpn_response = ec2_client.create_vpn_connection(
            CustomerGatewayId=customer_gateway_id,
            Type='ipsec.1',
            Options={'StaticRoutesOnly': False},
            TagSpecifications=[{
                'ResourceType': 'vpn-connection',
                'Tags': [{'Key': 'Name', 'Value': 'onpremises'}]
            }]
        )
        
        vpn_connection_id = vpn_response['VpnConnection']['VpnConnectionId']
        print(f"✓ Created VPN connection: {vpn_connection_id}")
        
        return {
            'status': 'success',
            'vpn_connection_id': vpn_connection_id,
            'customer_gateway_id': customer_gateway_id
        }
        
    except Exception as e:
        error_msg = str(e)
        # Check if it's an "already exists" error
        if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
            print(f"VPN connection already exists, continuing...")
            return {'status': 'success', 'vpn_connection_id': None, 'customer_gateway_id': None}
        print(f"Error creating Site-to-Site VPN: {e}")
        return {'status': 'failed', 'error': str(e)}


def wait_for_vpn_available(ec2_client, vpn_connection_id: str, max_wait: int = 300):
    """Wait for VPN connection to become available"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = ec2_client.describe_vpn_connections(VpnConnectionIds=[vpn_connection_id])
            
            if response['VpnConnections']:
                state = response['VpnConnections'][0]['State']
                
                if state == 'available':
                    print("✓ VPN connection is now available")
                    return True
                elif state in ['pending', 'creating']:
                    print(f"VPN connection state: {state}")
                    time.sleep(30)
                else:
                    print(f"Unexpected VPN state: {state}")
                    return False
            
        except Exception as e:
            print(f"Error checking VPN status: {e}")
            time.sleep(30)
    
    print("Timeout waiting for VPN to become available")
    return False


def update_vpc_route_tables(session, core_network_id: str) -> List[Dict[str, Any]]:
    """Update VPC route tables to point to CloudWAN core network"""
    results = []
    account_id = get_account_id(session)
    
    for region in REGION_MAP.values():
        print(f"\nUpdating route tables in {region}...")
        ec2_client = session.client('ec2', region_name=region)
        
        for config in ROUTE_CONFIGS:
            vpc_name = config["vpc_name"]
            route_table_name = config["route_table_name"]
            destination = config["destination"]
            
            print(f"Processing {vpc_name} - {route_table_name} route table...")
            
            vpc_id = get_vpc_id_by_name(ec2_client, vpc_name)
            if not vpc_id:
                print(f"  VPC not found: {vpc_name}")
                results.append({
                    'region': region, 'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'status': 'Failed - VPC not found'
                })
                continue
            
            print(f"  Found VPC: {vpc_id}")
            route_table_ids = get_route_table_ids(ec2_client, vpc_id, route_table_name)
            if not route_table_ids:
                print(f"  No route tables found matching: {route_table_name}")
                results.append({
                    'region': region, 'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'status': 'Failed - Route table not found'
                })
                continue
            
            for rt_id in route_table_ids:
                success = update_route_table(ec2_client, rt_id, destination, core_network_id, account_id)
                results.append({
                    'region': region, 'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'route_table_id': rt_id, 'destination': destination,
                    'status': 'Updated' if success else 'Failed'
                })
                print(f"{'✓' if success else '✗'} {'Updated' if success else 'Failed to update'} route table {rt_id}")
    
    return results


def get_vpc_id_by_name(ec2_client, vpc_name_pattern: str) -> Optional[str]:
    """Get VPC ID by name tag pattern (supports wildcards with *)"""
    import re
    try:
        response = ec2_client.describe_vpcs()
        
        # Convert wildcard pattern to simple matching
        pattern = vpc_name_pattern.replace('*', '.*')
        regex = re.compile(f'^{pattern}$')
        
        for vpc in response['Vpcs']:
            for tag in vpc.get('Tags', []):
                if tag['Key'] == 'Name' and regex.match(tag['Value']):
                    return vpc['VpcId']
        return None
    except Exception as e:
        print(f"Error finding VPC {vpc_name_pattern}: {e}")
        return None


def get_route_table_ids(ec2_client, vpc_id: str, route_table_name_pattern: str) -> List[str]:
    """Get route table IDs by VPC and name pattern (supports wildcards)"""
    import re
    try:
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        # Convert wildcard pattern to regex
        pattern = route_table_name_pattern.replace('*', '.*')
        regex = re.compile(f'^{pattern}$', re.IGNORECASE)
        
        result = []
        for rt in response['RouteTables']:
            for tag in rt.get('Tags', []):
                if tag['Key'] == 'Name' and regex.match(tag['Value']):
                    result.append(rt['RouteTableId'])
                    break
        return result
    except Exception as e:
        print(f"Error finding route tables for VPC {vpc_id}: {e}")
        return []


def update_route_table(ec2_client, route_table_id: str, destination: str, core_network_id: str, account_id: str) -> bool:
    """Update a single route table with core network route"""
    try:
        response = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
        existing_routes = response['RouteTables'][0]['Routes']
        
        core_network_arn = f"arn:aws:networkmanager::{account_id}:core-network/{core_network_id}"
        
        for route in existing_routes:
            if route.get('DestinationCidrBlock') == destination:
                ec2_client.replace_route(
                    RouteTableId=route_table_id,
                    DestinationCidrBlock=destination,
                    CoreNetworkArn=core_network_arn
                )
                return True
        
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock=destination,
            CoreNetworkArn=core_network_arn
        )
        return True
        
    except Exception as e:
        error_msg = str(e)
        # Check if route already exists
        if 'routealreadyexists' in error_msg.lower().replace(' ', ''):
            print(f"Route already exists in {route_table_id}, continuing...")
            return True
        print(f"Error updating route table {route_table_id}: {e}")
        return False


def get_vpn_connections(ec2_client) -> List[Dict[str, str]]:
    """Get available VPN connections in the region"""
    try:
        response = ec2_client.describe_vpn_connections(
            Filters=[{'Name': 'state', 'Values': ['available']}]
        )
        return [{'VpnConnectionId': vpn['VpnConnectionId'], 'State': vpn['State']} 
                for vpn in response['VpnConnections']]
    except Exception as e:
        print(f"Warning: Could not fetch VPN connections: {e}")
        return []


def create_cloudwan_vpn_attachment(nm_client, core_network_id: str, config: VPNAttachmentConfig, 
                                    vpn_id: str, account_id: str) -> Dict[str, Any]:
    """Create a CloudWAN VPN attachment"""
    try:
        response = nm_client.create_site_to_site_vpn_attachment(
            CoreNetworkId=core_network_id,
            VpnConnectionArn=f"arn:aws:ec2:{config.edge_location}:{account_id}:vpn-connection/{vpn_id}",
            Tags=[
                {'Key': config.tag_key, 'Value': config.tag_value},
                {'Key': 'Name', 'Value': config.name}
            ]
        )
        return response
    except Exception as e:
        error_msg = str(e)
        # Check if it's an "already attached" error
        if 'already attached' in error_msg.lower():
            print(f"VPN already attached to Core Network, continuing...")
            return {'SiteToSiteVpnAttachment': {'AttachmentId': 'existing'}}
        print(f"Error creating VPN attachment {config.name}: {e}")
        return {}


def get_subnets_for_vpc(ec2_client, vpc_id: str) -> List[str]:
    """Get CWAN subnet IDs for a VPC, one per AZ"""
    try:
        response = ec2_client.describe_subnets(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'tag:Name', 'Values': ['*cwan*', '*CWAN*']}
            ]
        )
        
        az_subnets = {}
        for subnet in response['Subnets']:
            az = subnet['AvailabilityZone']
            if az not in az_subnets:
                az_subnets[az] = subnet['SubnetId']
        
        return list(az_subnets.values())
    except Exception as e:
        print(f"Warning: Could not fetch subnets for {vpc_id}: {e}")
        return []


def create_cloudwan_attachment(nm_client, core_network_id: str, config: AttachmentConfig, 
                                subnet_ids: List[str], account_id: str) -> Dict[str, Any]:
    """Create a CloudWAN VPC attachment"""
    region = REGION_MAP[config.edge_location]
    
    params = {
        'CoreNetworkId': core_network_id,
        'VpcArn': f"arn:aws:ec2:{region}:{account_id}:vpc/{config.vpc_id}",
        'SubnetArns': [f"arn:aws:ec2:{region}:{account_id}:subnet/{sid}" for sid in subnet_ids],
        'Tags': [
            {'Key': config.tag_key, 'Value': config.tag_value},
            {'Key': 'Name', 'Value': config.name}
        ]
    }
    
    if config.appliance_mode:
        params['Options'] = {'ApplianceModeSupport': True}
    
    try:
        return nm_client.create_vpc_attachment(**params)
    except Exception as e:
        error_msg = str(e)
        # Check if it's an "already exists" error
        if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
            print(f"Attachment already exists for {config.name}, continuing...")
            return {'VpcAttachment': {'AttachmentId': 'existing'}}
        print(f"Error creating attachment {config.name}: {e}")
        return {}


def create_all_attachments(session, core_network_id: str) -> List[Dict[str, Any]]:
    """Create all VPC and VPN attachments"""
    account_id = get_account_id(session)
    nm_client = session.client('networkmanager', region_name='us-west-2')
    
    attachments_config = [
        # Stockholm
        AttachmentConfig("stockholm-prod", "stockholm", False, "prod-vpc-*", "domain", "prod"),
        AttachmentConfig("stockholm-thirdparty", "stockholm", False, "thirdparty-vpc-*", "domain", "thirdparty"),
        AttachmentConfig("stockholm-eastwestinspection", "stockholm", True, "eastwest-inspection-vpc-*", "nfg", "eastwestinspection"),
        AttachmentConfig("stockholm-egressinspection", "stockholm", True, "egress-inspection-vpc-*", "nfg", "egressinspection"),
        # Oregon
        AttachmentConfig("oregon-prod", "oregon", False, "prod-vpc-*", "domain", "prod"),
        AttachmentConfig("oregon-thirdparty", "oregon", False, "thirdparty-vpc-*", "domain", "thirdparty"),
        AttachmentConfig("oregon-eastwestinspection", "oregon", True, "eastwest-inspection-vpc-*", "nfg", "eastwestinspection"),
        AttachmentConfig("oregon-egressinspection", "oregon", True, "egress-inspection-vpc-*", "nfg", "egressinspection"),
    ]
    
    vpn_attachments_config = [
        VPNAttachmentConfig("stockholm-onpremises-vpn", "eu-north-1", "domain", "onpremises"),
    ]
    
    results = []
    
    # Process VPC attachments
    for config in attachments_config:
        region = REGION_MAP[config.edge_location]
        print(f"\nProcessing {config.name} in {region}...")
        
        ec2_client = session.client('ec2', region_name=region)
        
        # Look up VPC ID by name pattern
        vpc_id = get_vpc_id_by_name(ec2_client, config.vpc_id)
        if not vpc_id:
            print(f"Warning: VPC not found matching pattern {config.vpc_id} in {region}")
            results.append({'name': config.name, 'region': region, 'status': 'Failed - VPC not found'})
            continue
        
        print(f"  Found VPC: {vpc_id}")
        subnet_ids = get_subnets_for_vpc(ec2_client, vpc_id)
        
        if not subnet_ids:
            print(f"Warning: No subnets found for {vpc_id} in {region}")
            results.append({'name': config.name, 'region': region, 'vpc_id': vpc_id, 'status': 'Failed - No subnets'})
            continue
        
        print(f"Found {len(subnet_ids)} subnets: {subnet_ids}")
        
        # Update config with actual VPC ID for attachment creation
        actual_config = AttachmentConfig(config.name, config.edge_location, config.appliance_mode, 
                                        vpc_id, config.tag_key, config.tag_value)
        result = create_cloudwan_attachment(nm_client, core_network_id, actual_config, subnet_ids, account_id)
        
        if result:
            attachment_id = result.get('VpcAttachment', {}).get('AttachmentId')
            results.append({'name': config.name, 'region': region, 'attachment_id': attachment_id, 'status': 'Created'})
            print(f"✓ Created attachment: {attachment_id}")
        else:
            results.append({'name': config.name, 'region': region, 'status': 'Failed'})
    
    # Process VPN attachments
    for vpn_config in vpn_attachments_config:
        region = vpn_config.edge_location
        print(f"\nProcessing VPN attachment {vpn_config.name} in {region}...")
        
        ec2_client = session.client('ec2', region_name=region)
        vpn_connections = get_vpn_connections(ec2_client)
        
        if not vpn_connections:
            print(f"Warning: No VPN connections found in {region}")
            results.append({'name': vpn_config.name, 'region': region, 'status': 'Failed - No VPN found'})
            continue
        
        vpn_id = vpn_connections[0]['VpnConnectionId']
        print(f"Using VPN connection: {vpn_id}")
        
        result = create_cloudwan_vpn_attachment(nm_client, core_network_id, vpn_config, vpn_id, account_id)
        
        if result:
            attachment_id = result.get('SiteToSiteVpnAttachment', {}).get('AttachmentId')
            results.append({'name': vpn_config.name, 'region': region, 'attachment_id': attachment_id, 
                           'vpn_id': vpn_id, 'status': 'Created'})
            print(f"✓ Created VPN attachment: {attachment_id}")
        else:
            results.append({'name': vpn_config.name, 'region': region, 'vpn_id': vpn_id, 'status': 'Failed'})
    
    return results


def load_env_file(env_file: str) -> Dict[str, str]:
    """Load AWS credentials from .env file"""
    creds = {}
    try:
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Remove 'export ' prefix if present
                if line.startswith('export '):
                    line = line[7:]
                # Parse key=value
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip().strip('"').strip("'")
                    creds[key] = value
        return creds
    except FileNotFoundError:
        print(f"Error: {env_file} not found")
        sys.exit(1)


def get_or_select_core_network(session) -> str:
    """Get core network ID, prompting user if multiple exist"""
    nm_client = session.client('networkmanager', region_name='us-west-2')
    
    try:
        response = nm_client.list_core_networks()
        core_networks = response.get('CoreNetworks', [])
        
        if not core_networks:
            print("Error: No core networks found in your account")
            sys.exit(1)
        
        if len(core_networks) == 1:
            cn_id = core_networks[0]['CoreNetworkId']
            print(f"Found core network: {cn_id}")
            return cn_id
        
        # Multiple core networks - prompt user
        print("\nMultiple core networks found:")
        for i, cn in enumerate(core_networks, 1):
            cn_id = cn['CoreNetworkId']
            state = cn['State']
            print(f"  {i}. {cn_id} (State: {state})")
        
        while True:
            try:
                choice = input("\nSelect core network (enter number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(core_networks):
                    return core_networks[idx]['CoreNetworkId']
                print(f"Invalid choice. Please enter a number between 1 and {len(core_networks)}")
            except (ValueError, KeyboardInterrupt):
                print("\nError: Invalid input")
                sys.exit(1)
                
    except Exception as e:
        print(f"Error listing core networks: {e}")
        sys.exit(1)


def extract_core_network_id(value: str) -> str:
    """Extract core network ID from ARN or return as-is if already an ID"""
    if value.startswith('arn:aws:networkmanager'):
        # Extract the ID from ARN like: arn:aws:networkmanager::522814688295:core-network/core-network-0848a6df024911780
        parts = value.split('/')
        if len(parts) >= 2:
            return parts[-1]
    return value


def main():
    parser = argparse.ArgumentParser(description='Deploy CloudWAN infrastructure')
    parser.add_argument('--aws-access-key-id', help='AWS Access Key ID')
    parser.add_argument('--aws-secret-access-key', help='AWS Secret Access Key')
    parser.add_argument('--aws-session-token', help='AWS Session Token (optional)')
    parser.add_argument('--env-file', help='Path to .env file with AWS credentials')
    parser.add_argument('--core-network-id', help='CloudWAN Core Network ID or ARN (optional, will auto-detect if not provided)')
    parser.add_argument('--step', choices=['2-update-core-network-policy', '3-configure-site-to-site-vpn', 
                                          '4-create-attachments', '5-update-core-network-policy-for-routing', 
                                          '7-update-vpc-route-tables', 'all'], 
                       default='all', help='Deployment step to execute (default: all)')
    
    args = parser.parse_args()
    
    # Load credentials from env file or command line
    if args.env_file:
        creds = load_env_file(args.env_file)
        access_key = creds.get('AWS_ACCESS_KEY_ID')
        secret_key = creds.get('AWS_SECRET_ACCESS_KEY')
        session_token = creds.get('AWS_SESSION_TOKEN')
    else:
        access_key = args.aws_access_key_id
        secret_key = args.aws_secret_access_key
        session_token = args.aws_session_token
    
    if not access_key or not secret_key:
        print("Error: AWS credentials required. Use --env-file or --aws-access-key-id/--aws-secret-access-key")
        parser.print_help()
        sys.exit(1)
    
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    )
    
    # Get or select core network ID
    if args.core_network_id:
        args.core_network_id = extract_core_network_id(args.core_network_id)
        print(f"Using Core Network ID: {args.core_network_id}")
    else:
        args.core_network_id = get_or_select_core_network(session)
    
    print(f"Executing step: {args.step}")
    
    results = {'steps_completed': [], 'errors': []}
    nm_client = session.client('networkmanager', region_name='us-west-2')
    
    # Step 2: Update Core Network Policy
    if args.step in ['2-update-core-network-policy', 'all']:
        print("\n" + "="*50)
        print("STEP 2: UPDATE CORE NETWORK POLICY")
        print("="*50)
        
        policy_result = deploy_network_policy(nm_client, args.core_network_id)
        
        if policy_result['status'] == 'success':
            results['steps_completed'].append('2-update-core-network-policy')
            print("✓ Network policy deployment completed")
        else:
            results['errors'].append(f"Policy deployment failed: {policy_result.get('error')}")
            print("✗ Network policy deployment failed")
            if args.step == 'all':
                print("\nStopping execution due to failure in 'all' mode")
                sys.exit(1)
            elif args.step == '2-update-core-network-policy':
                sys.exit(1)
    
    # Step 3: Configure Site-to-Site VPN
    if args.step in ['3-configure-site-to-site-vpn', 'all']:
        print("\n" + "="*50)
        print("STEP 3: CONFIGURE SITE-TO-SITE VPN")
        print("="*50)
        
        london_ec2 = session.client('ec2', region_name='eu-west-2')
        onprem_ip = get_onprem_instance_ip(london_ec2)
        
        if not onprem_ip:
            results['errors'].append("Could not find onprem instance IP in eu-west-2")
            print("✗ Could not find onprem instance IP in eu-west-2")
            if args.step == 'all':
                print("\nStopping execution due to failure in 'all' mode")
                sys.exit(1)
            elif args.step == '3-configure-site-to-site-vpn':
                sys.exit(1)
        else:
            print(f"Found onprem instance IP: {onprem_ip}")
            
            stockholm_ec2 = session.client('ec2', region_name='eu-north-1')
            vpn_result = create_site_to_site_vpn(stockholm_ec2, onprem_ip)
            
            if vpn_result['status'] == 'success':
                vpn_id = vpn_result['vpn_connection_id']
                if wait_for_vpn_available(stockholm_ec2, vpn_id):
                    results['steps_completed'].append('3-configure-site-to-site-vpn')
                    results['vpn_connection_id'] = vpn_id
                    print("✓ Site-to-Site VPN creation completed")
                else:
                    results['errors'].append("VPN creation timed out")
                    print("✗ VPN creation timed out")
                    if args.step == 'all':
                        print("\nStopping execution due to failure in 'all' mode")
                        sys.exit(1)
            else:
                results['errors'].append(f"VPN creation failed: {vpn_result.get('error')}")
                print("✗ Site-to-Site VPN creation failed")
                if args.step == 'all':
                    print("\nStopping execution due to failure in 'all' mode")
                    sys.exit(1)
                elif args.step == '3-configure-site-to-site-vpn':
                    sys.exit(1)
    
    # Step 4: Create Attachments
    if args.step in ['4-create-attachments', 'all']:
        print("\n" + "="*50)
        print("STEP 4: CREATE ATTACHMENTS")
        print("="*50)
        
        attachment_results = create_all_attachments(session, args.core_network_id)
        
        if attachment_results:
            results['steps_completed'].append('4-create-attachments')
            results['attachments'] = attachment_results
            print("✓ Attachment creation completed")
            
            # Wait for attachments to be available before continuing
            if args.step == 'all':
                print("\nWaiting for attachments to be available...")
                if not wait_for_attachments_available(nm_client, args.core_network_id):
                    results['errors'].append("Attachment creation failed or timed out")
                    print("\nStopping execution due to failure in 'all' mode")
                    sys.exit(1)
        else:
            results['errors'].append("Attachment creation failed")
            print("✗ Attachment creation failed")
    
    # Step 5: Update Core Network Policy for Routing
    if args.step in ['5-update-core-network-policy-for-routing', 'all']:
        print("\n" + "="*50)
        print("STEP 5: UPDATE CORE NETWORK POLICY FOR ROUTING")
        print("="*50)
        
        routing_result = deploy_network_policy(nm_client, args.core_network_id, "routing")
        
        if routing_result['status'] == 'success':
            results['steps_completed'].append('5-update-core-network-policy-for-routing')
            results['routing_policy_version_id'] = routing_result['policy_version_id']
            print("✓ Routing policy deployment completed")
        else:
            results['errors'].append(f"Routing policy deployment failed: {routing_result.get('error')}")
            print("✗ Routing policy deployment failed")
            if args.step == 'all':
                print("\nStopping execution due to failure in 'all' mode")
                sys.exit(1)
            elif args.step == '5-update-core-network-policy-for-routing':
                sys.exit(1)
    
    # Step 7: Update VPC Route Tables
    if args.step in ['7-update-vpc-route-tables', 'all']:
        print("\n" + "="*50)
        print("STEP 7: UPDATE VPC ROUTE TABLES")
        print("="*50)
        
        route_results = update_vpc_route_tables(session, args.core_network_id)
        
        if route_results:
            results['steps_completed'].append('7-update-vpc-route-tables')
            results['route_updates'] = route_results
            
            successful = len([r for r in route_results if r['status'] == 'Updated'])
            total = len(route_results)
            
            print(f"✓ Route table updates completed: {successful}/{total} successful")
            
            if successful < total:
                results['errors'].append(f"{total - successful} route table updates failed")
                if args.step == 'all':
                    print("\nStopping execution due to failure in 'all' mode")
                    sys.exit(1)
        else:
            results['errors'].append("Route table update failed")
            print("✗ Route table update failed")
            if args.step == 'all':
                print("\nStopping execution due to failure in 'all' mode")
                sys.exit(1)
            elif args.step == '7-update-vpc-route-tables':
                sys.exit(1)
    
    # Final Summary
    print("\n" + "="*60)
    print("DEPLOYMENT SUMMARY")
    print("="*60)
    
    print(f"Steps completed: {', '.join(results['steps_completed'])}")
    if results['errors']:
        print(f"Errors encountered: {len(results['errors'])}")
        for error in results['errors']:
            print(f"  - {error}")


if __name__ == "__main__":
    main()
