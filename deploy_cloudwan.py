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
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class DeploymentStep(Enum):
    POLICY = "policy"
    VPN = "vpn"
    ATTACHMENTS = "attachments"
    ROUTING = "routing"
    ROUTES = "routes"
    ALL = "all"


@dataclass
class AttachmentConfig:
    name: str
    edge_location: str
    attachment_type: str
    appliance_mode: str
    vpc_id: str
    subnet_strategy: str
    tag_key: str
    tag_value: str


@dataclass
class VPNAttachmentConfig:
    name: str
    edge_location: str
    attachment_type: str
    vpn_id: str
    tag_key: str
    tag_value: str


def get_network_policy(step: str = "initial") -> Dict[str, Any]:
    """Load the CloudWAN network policy from JSON file"""
    filename = 'step1-cnp.json' if step == "initial" else 'step4-routing-cnp.json'
    
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {filename} file not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing {filename}: {e}")
        sys.exit(1)


def deploy_network_policy(networkmanager_client, core_network_id: str, step: str = "initial") -> Dict[str, Any]:
    """Deploy the network policy to CloudWAN core network"""
    policy = get_network_policy(step)
    description = "CloudWAN network policy with segments and NFGs" if step == "initial" else "CloudWAN routing policy with segment actions"
    
    try:
        print(f"Deploying {step} network policy...")
        response = networkmanager_client.put_core_network_policy(
            CoreNetworkId=core_network_id,
            PolicyDocument=json.dumps(policy),
            Description=description
        )
        
        policy_version_id = response['CoreNetworkPolicy']['PolicyVersionId']
        print(f"✓ Policy created with version ID: {policy_version_id}")
        
        # Execute the policy
        print("Executing policy...")
        execute_response = networkmanager_client.execute_core_network_change_set(
            CoreNetworkId=core_network_id,
            PolicyVersionId=policy_version_id
        )
        
        print("✓ Policy execution initiated")
        
        # Wait for policy to be executed
        print("Waiting for policy execution to complete...")
        wait_for_policy_execution(networkmanager_client, core_network_id)
        
        return {
            'status': 'success',
            'policy_version_id': policy_version_id,
            'execution_response': execute_response
        }
        
    except Exception as e:
        print(f"Error deploying network policy: {e}")
        return {'status': 'failed', 'error': str(e)}


def wait_for_policy_execution(networkmanager_client, core_network_id: str, max_wait: int = 600):
    """Wait for policy execution to complete"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = networkmanager_client.get_core_network(CoreNetworkId=core_network_id)
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
    """Get the public IP of the onprem EC2 instance in eu-west-2"""
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': ['onprem']},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                public_ip = instance.get('PublicIpAddress')
                if public_ip:
                    return public_ip
        
        return None
    
    except Exception as e:
        print(f"Error getting onprem instance IP: {e}")
        return None


def create_site_to_site_vpn(ec2_client, onprem_ip: str) -> Dict[str, Any]:
    """Create Site-to-Site VPN connection in Stockholm"""
    try:
        print(f"Creating Site-to-Site VPN with onprem IP: {onprem_ip}")
        
        # Create customer gateway first
        cgw_response = ec2_client.create_customer_gateway(
            BgpAsn=64512,
            PublicIp=onprem_ip,
            Type='ipsec.1',
            TagSpecifications=[
                {
                    'ResourceType': 'customer-gateway',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'onpremises-cgw'}
                    ]
                }
            ]
        )
        
        customer_gateway_id = cgw_response['CustomerGateway']['CustomerGatewayId']
        print(f"✓ Created customer gateway: {customer_gateway_id}")
        
        # Create VPN connection
        vpn_response = ec2_client.create_vpn_connection(
            CustomerGatewayId=customer_gateway_id,
            Type='ipsec.1',
            Options={
                'StaticRoutesOnly': False  # Dynamic routing with BGP
            },
            TagSpecifications=[
                {
                    'ResourceType': 'vpn-connection',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'onpremises'}
                    ]
                }
            ]
        )
        
        vpn_connection_id = vpn_response['VpnConnection']['VpnConnectionId']
        print(f"✓ Created VPN connection: {vpn_connection_id}")
        
        return {
            'status': 'success',
            'vpn_connection_id': vpn_connection_id,
            'customer_gateway_id': customer_gateway_id
        }
        
    except Exception as e:
        print(f"Error creating Site-to-Site VPN: {e}")
        return {'status': 'failed', 'error': str(e)}


def wait_for_vpn_available(ec2_client, vpn_connection_id: str, max_wait: int = 300):
    """Wait for VPN connection to become available"""
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        try:
            response = ec2_client.describe_vpn_connections(
                VpnConnectionIds=[vpn_connection_id]
            )
            
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


def get_core_network_arn(networkmanager_client, core_network_id: str) -> str:
    """Get the ARN of the core network"""
    try:
        response = networkmanager_client.get_core_network(CoreNetworkId=core_network_id)
        return response['CoreNetwork']['CoreNetworkArn']
    except Exception as e:
        print(f"Error getting core network ARN: {e}")
        return ""


def update_vpc_route_tables(session, core_network_id: str) -> List[Dict[str, Any]]:
    """Update VPC route tables to point to CloudWAN core network"""
    
    # Route table configurations per region
    route_configs = {
        "eu-north-1": [  # Stockholm
            {"vpc_name": "VPC-prod", "route_table_name": "private", "destination": "0.0.0.0/0"},
            {"vpc_name": "VPC-thirdparty", "route_table_name": "private", "destination": "0.0.0.0/0"},
            {"vpc_name": "eastwest-inspection", "route_table_name": "firewall", "destination": "0.0.0.0/0"},
            {"vpc_name": "egress-inspection", "route_table_name": "firewall", "destination": "10.0.0.0/8"},
        ],
        "us-west-2": [  # Oregon
            {"vpc_name": "VPC-prod", "route_table_name": "private", "destination": "0.0.0.0/0"},
            {"vpc_name": "VPC-thirdparty", "route_table_name": "private", "destination": "0.0.0.0/0"},
            {"vpc_name": "eastwest-inspection", "route_table_name": "firewall", "destination": "0.0.0.0/0"},
            {"vpc_name": "egress-inspection", "route_table_name": "firewall", "destination": "10.0.0.0/8"},
        ]
    }
    
    # Get core network ARN
    networkmanager_client = session.client('networkmanager', region_name='us-west-2')
    core_network_arn = get_core_network_arn(networkmanager_client, core_network_id)
    
    if not core_network_arn:
        print("Failed to get core network ARN")
        return []
    
    results = []
    
    for region, configs in route_configs.items():
        print(f"\nUpdating route tables in {region}...")
        ec2_client = session.client('ec2', region_name=region)
        
        for config in configs:
            vpc_name = config["vpc_name"]
            route_table_name = config["route_table_name"]
            destination = config["destination"]
            
            print(f"Processing {vpc_name} - {route_table_name} route table...")
            
            # Find VPC ID
            vpc_id = get_vpc_id_by_name(ec2_client, vpc_name)
            if not vpc_id:
                results.append({
                    'region': region,
                    'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'status': 'Failed - VPC not found'
                })
                continue
            
            # Find route table IDs
            route_table_ids = get_route_table_ids(ec2_client, vpc_id, route_table_name)
            if not route_table_ids:
                results.append({
                    'region': region,
                    'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'status': 'Failed - Route table not found'
                })
                continue
            
            # Update each route table
            for rt_id in route_table_ids:
                success = update_route_table(ec2_client, rt_id, destination, core_network_id)
                results.append({
                    'region': region,
                    'vpc_name': vpc_name,
                    'route_table_name': route_table_name,
                    'route_table_id': rt_id,
                    'destination': destination,
                    'status': 'Updated' if success else 'Failed'
                })
                
                if success:
                    print(f"✓ Updated route table {rt_id}")
                else:
                    print(f"✗ Failed to update route table {rt_id}")
    
    return results


def get_vpc_id_by_name(ec2_client, vpc_name: str) -> Optional[str]:
    """Get VPC ID by name tag"""
    try:
        response = ec2_client.describe_vpcs(
            Filters=[
                {'Name': 'tag:Name', 'Values': [vpc_name]}
            ]
        )
        
        if response['Vpcs']:
            return response['Vpcs'][0]['VpcId']
        return None
        
    except Exception as e:
        print(f"Error finding VPC {vpc_name}: {e}")
        return None


def get_route_table_ids(ec2_client, vpc_id: str, route_table_name: str) -> List[str]:
    """Get route table IDs by VPC and name pattern"""
    try:
        response = ec2_client.describe_route_tables(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'tag:Name', 'Values': [f'*{route_table_name}*']}
            ]
        )
        
        return [rt['RouteTableId'] for rt in response['RouteTables']]
        
    except Exception as e:
        print(f"Error finding route tables for VPC {vpc_id}: {e}")
        return []


def update_route_table(ec2_client, route_table_id: str, destination: str, core_network_id: str) -> bool:
    """Update a single route table with core network route"""
    try:
        # Check if route already exists
        response = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
        existing_routes = response['RouteTables'][0]['Routes']
        
        # Check if route to destination already exists
        for route in existing_routes:
            if route.get('DestinationCidrBlock') == destination:
                # Route exists, replace it
                try:
                    ec2_client.replace_route(
                        RouteTableId=route_table_id,
                        DestinationCidrBlock=destination,
                        CoreNetworkArn=f"arn:aws:networkmanager::*:core-network/{core_network_id}"
                    )
                    return True
                except Exception as e:
                    print(f"Error replacing route: {e}")
                    return False
        
        # Route doesn't exist, create it
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock=destination,
            CoreNetworkArn=f"arn:aws:networkmanager::*:core-network/{core_network_id}"
        )
        return True
        
    except Exception as e:
        print(f"Error updating route table {route_table_id}: {e}")
        return False


def get_vpn_connections(ec2_client, region: str) -> List[Dict[str, str]]:
    """Get available VPN connections in the region"""
    try:
        response = ec2_client.describe_vpn_connections(
            Filters=[
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        vpn_connections = []
        for vpn in response['VpnConnections']:
            vpn_connections.append({
                'VpnConnectionId': vpn['VpnConnectionId'],
                'State': vpn['State']
            })
        
        return vpn_connections
    
    except Exception as e:
        print(f"Warning: Could not fetch VPN connections in {region}: {e}")
        return []


def create_cloudwan_vpn_attachment(networkmanager_client, core_network_id: str, config: VPNAttachmentConfig, vpn_id: str) -> Dict[str, Any]:
    """Create a CloudWAN VPN attachment"""
    
    # Get account ID from STS
    sts_client = networkmanager_client._client_config.__dict__.get('_user_provided_options', {}).get('region_name', 'us-west-2')
    sts = boto3.client('sts', region_name=sts_client if isinstance(sts_client, str) else 'us-west-2')
    account_id = sts.get_caller_identity()['Account']
    
    attachment_params = {
        'CoreNetworkId': core_network_id,
        'VpnConnectionArn': f"arn:aws:ec2:{config.edge_location}:{account_id}:vpn-connection/{vpn_id}",
        'Tags': {
            config.tag_key: config.tag_value,
            'Name': config.name
        }
    }
    
    try:
        response = networkmanager_client.create_site_to_site_vpn_attachment(**attachment_params)
        return response
    except Exception as e:
        print(f"Error creating VPN attachment {config.name}: {e}")
        return {}


def get_subnets_for_vpc(ec2_client, vpc_id: str, strategy: str = "CWAN in each AZ") -> List[str]:
    """Get subnet IDs for a VPC based on the strategy"""
    try:
        response = ec2_client.describe_subnets(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'tag:Name', 'Values': ['*cwan*', '*CWAN*']}
            ]
        )
        
        # Group by AZ and take one subnet per AZ
        az_subnets = {}
        for subnet in response['Subnets']:
            az = subnet['AvailabilityZone']
            if az not in az_subnets:
                az_subnets[az] = subnet['SubnetId']
        
        return list(az_subnets.values())
    
    except Exception as e:
        print(f"Warning: Could not fetch subnets for {vpc_id}: {e}")
        return []


def create_cloudwan_attachment(networkmanager_client, core_network_id: str, config: AttachmentConfig, subnet_ids: List[str]) -> Dict[str, Any]:
    """Create a CloudWAN VPC attachment"""
    
    attachment_params = {
        'CoreNetworkId': core_network_id,
        'VpcArn': f"arn:aws:ec2:{config.edge_location}:{{account_id}}:vpc/{config.vpc_id}",
        'SubnetArns': [f"arn:aws:ec2:{config.edge_location}:{{account_id}}:subnet/{subnet_id}" for subnet_id in subnet_ids],
        'Tags': {
            config.tag_key: config.tag_value,
            'Name': config.name
        }
    }
    
    # Add appliance mode if specified
    if config.appliance_mode.lower() == 'enable':
        attachment_params['Options'] = {'ApplianceModeSupport': True}
    
    try:
        response = networkmanager_client.create_vpc_attachment(**attachment_params)
        return response
    except Exception as e:
        print(f"Error creating attachment {config.name}: {e}")
        return {}


def create_all_attachments(session, core_network_id: str) -> List[Dict[str, Any]]:
    """Create all VPC and VPN attachments"""
    # Configuration for all attachments
    attachments_config = [
        # Stockholm Region
        AttachmentConfig("stockholm-prod", "stockholm", "VPC", "", "VPC-prod", "CWAN in each AZ", "domain", "prod"),
        AttachmentConfig("stockholm-thirdparty", "stockholm", "VPC", "", "VPC-thirdparty", "CWAN in each AZ", "domain", "thirdparty"),
        AttachmentConfig("stockholm-eastwestinspection", "stockholm", "VPC", "Enable", "eastwest-inspection", "CWAN in each AZ", "nfg", "eastwestinspection"),
        AttachmentConfig("stockholm-egressinspection", "stockholm", "VPC", "Enable", "egress-inspection", "CWAN in each AZ", "nfg", "egressinspection"),
        
        # Oregon Region
        AttachmentConfig("oregon-prod", "oregon", "VPC", "", "VPC-prod", "CWAN in each AZ", "domain", "prod"),
        AttachmentConfig("oregon-thirdparty", "oregon", "VPC", "", "VPC-thirdparty", "CWAN in each AZ", "domain", "thirdparty"),
        AttachmentConfig("oregon-eastwestinspection", "oregon", "VPC", "Enable", "eastwest-inspection", "CWAN in each AZ", "nfg", "eastwestinspection"),
        AttachmentConfig("oregon-egressinspection", "oregon", "VPC", "Enable", "egress-inspection", "CWAN in each AZ", "nfg", "egressinspection"),
    ]
    
    # VPN Attachments configuration
    vpn_attachments_config = [
        VPNAttachmentConfig("stockholm-onpremises-vpn", "eu-north-1", "VPN", "", "domain", "onpremises"),
    ]
    
    # Region mapping
    region_mapping = {
        "stockholm": "eu-north-1",
        "oregon": "us-west-2"
    }
    
    results = []
    
    # Process VPC attachments
    for config in attachments_config:
        region = region_mapping[config.edge_location]
        print(f"\nProcessing {config.name} in {region}...")
        
        # Initialize clients for the region using the session
        ec2_client = session.client('ec2', region_name=region)
        networkmanager_client = session.client('networkmanager', region_name='us-west-2')  # Global service
        
        # Get subnet IDs
        subnet_ids = get_subnets_for_vpc(ec2_client, config.vpc_id, config.subnet_strategy)
        
        if not subnet_ids:
            print(f"Warning: No subnets found for {config.vpc_id} in {region}")
            continue
        
        print(f"Found {len(subnet_ids)} subnets: {subnet_ids}")
        
        # Create the attachment
        result = create_cloudwan_attachment(networkmanager_client, core_network_id, config, subnet_ids)
        
        if result:
            results.append({
                'name': config.name,
                'region': region,
                'attachment_id': result.get('VpcAttachment', {}).get('AttachmentId'),
                'status': 'Created'
            })
            print(f"✓ Created attachment: {result.get('VpcAttachment', {}).get('AttachmentId')}")
        else:
            results.append({
                'name': config.name,
                'region': region,
                'status': 'Failed'
            })
    
    # Process VPN attachments
    for vpn_config in vpn_attachments_config:
        region = vpn_config.edge_location
        print(f"\nProcessing VPN attachment {vpn_config.name} in {region}...")
        
        # Initialize clients for the region using the session
        ec2_client = session.client('ec2', region_name=region)
        networkmanager_client = session.client('networkmanager', region_name='us-west-2')  # Global service
        
        # Get available VPN connections
        vpn_connections = get_vpn_connections(ec2_client, region)
        
        if not vpn_connections:
            print(f"Warning: No VPN connections found in {region}")
            results.append({
                'name': vpn_config.name,
                'region': region,
                'status': 'Failed - No VPN found'
            })
            continue
        
        # Use the first available VPN connection
        vpn_id = vpn_connections[0]['VpnConnectionId']
        print(f"Using VPN connection: {vpn_id}")
        
        # Create the VPN attachment
        result = create_cloudwan_vpn_attachment(networkmanager_client, core_network_id, vpn_config, vpn_id)
        
        if result:
            results.append({
                'name': vpn_config.name,
                'region': region,
                'attachment_id': result.get('SiteToSiteVpnAttachment', {}).get('AttachmentId'),
                'vpn_id': vpn_id,
                'status': 'Created'
            })
            print(f"✓ Created VPN attachment: {result.get('SiteToSiteVpnAttachment', {}).get('AttachmentId')}")
        else:
            results.append({
                'name': vpn_config.name,
                'region': region,
                'vpn_id': vpn_id,
                'status': 'Failed'
            })
    
    return results


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Deploy CloudWAN infrastructure')
    parser.add_argument('--aws-access-key-id', required=True, help='AWS Access Key ID')
    parser.add_argument('--aws-secret-access-key', required=True, help='AWS Secret Access Key')
    parser.add_argument('--core-network-id', required=True, help='CloudWAN Core Network ID')
    parser.add_argument('--aws-session-token', help='AWS Session Token (optional)')
    parser.add_argument('--step', choices=['policy', 'vpn', 'attachments', 'routing', 'routes', 'all'], default='all',
                       help='Deployment step to execute (default: all)')
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.aws_access_key_id or not args.aws_secret_access_key or not args.core_network_id:
        print("Error: Missing required arguments")
        parser.print_help()
        sys.exit(1)
    
    # Configure AWS credentials
    session = boto3.Session(
        aws_access_key_id=args.aws_access_key_id,
        aws_secret_access_key=args.aws_secret_access_key,
        aws_session_token=args.aws_session_token
    )
    
    print(f"Using Core Network ID: {args.core_network_id}")
    print(f"Executing step: {args.step}")
    
    results = {'steps_completed': [], 'errors': []}
    
    # Step 1: Deploy Network Policy
    if args.step in ['policy', 'all']:
        print("\n" + "="*50)
        print("STEP 1: DEPLOYING NETWORK POLICY")
        print("="*50)
        
        networkmanager_client = session.client('networkmanager', region_name='us-west-2')
        policy_result = deploy_network_policy(networkmanager_client, args.core_network_id)
        
        if policy_result['status'] == 'success':
            results['steps_completed'].append('policy')
            print("✓ Network policy deployment completed")
        else:
            results['errors'].append(f"Policy deployment failed: {policy_result.get('error')}")
            print("✗ Network policy deployment failed")
            if args.step == 'policy':
                sys.exit(1)
    
    # Step 2: Create Site-to-Site VPN
    if args.step in ['vpn', 'all']:
        print("\n" + "="*50)
        print("STEP 2: CREATING SITE-TO-SITE VPN")
        print("="*50)
        
        # Get onprem instance IP from London region
        london_ec2_client = session.client('ec2', region_name='eu-west-2')
        onprem_ip = get_onprem_instance_ip(london_ec2_client)
        
        if not onprem_ip:
            error_msg = "Could not find onprem instance IP in eu-west-2"
            results['errors'].append(error_msg)
            print(f"✗ {error_msg}")
            if args.step == 'vpn':
                sys.exit(1)
        else:
            print(f"Found onprem instance IP: {onprem_ip}")
            
            # Create VPN in Stockholm region
            stockholm_ec2_client = session.client('ec2', region_name='eu-north-1')
            vpn_result = create_site_to_site_vpn(stockholm_ec2_client, onprem_ip)
            
            if vpn_result['status'] == 'success':
                # Wait for VPN to become available
                vpn_id = vpn_result['vpn_connection_id']
                if wait_for_vpn_available(stockholm_ec2_client, vpn_id):
                    results['steps_completed'].append('vpn')
                    results['vpn_connection_id'] = vpn_id
                    print("✓ Site-to-Site VPN creation completed")
                else:
                    results['errors'].append("VPN creation timed out")
                    print("✗ VPN creation timed out")
            else:
                results['errors'].append(f"VPN creation failed: {vpn_result.get('error')}")
                print("✗ Site-to-Site VPN creation failed")
                if args.step == 'vpn':
                    sys.exit(1)
    
    # Step 3: Create Attachments
    if args.step in ['attachments', 'all']:
        print("\n" + "="*50)
        print("STEP 3: CREATING ATTACHMENTS")
        print("="*50)
        
        attachment_results = create_all_attachments(session, args.core_network_id)
        
        if attachment_results:
            results['steps_completed'].append('attachments')
            results['attachments'] = attachment_results
            print("✓ Attachment creation completed")
        else:
            results['errors'].append("Attachment creation failed")
            print("✗ Attachment creation failed")
    
    # Step 4: Update Core Network Policy for Routing
    if args.step in ['routing', 'all']:
        print("\n" + "="*50)
        print("STEP 4: UPDATING CORE NETWORK POLICY FOR ROUTING")
        print("="*50)
        
        networkmanager_client = session.client('networkmanager', region_name='us-west-2')
        routing_policy_result = deploy_network_policy(networkmanager_client, args.core_network_id, "routing")
        
        if routing_policy_result['status'] == 'success':
            results['steps_completed'].append('routing')
            results['routing_policy_version_id'] = routing_policy_result['policy_version_id']
            print("✓ Routing policy deployment completed")
        else:
            results['errors'].append(f"Routing policy deployment failed: {routing_policy_result.get('error')}")
            print("✗ Routing policy deployment failed")
            if args.step == 'routing':
                sys.exit(1)
    
    # Step 5: Update VPC Route Tables
    if args.step in ['routes', 'all']:
        print("\n" + "="*50)
        print("STEP 5: UPDATING VPC ROUTE TABLES")
        print("="*50)
        
        route_results = update_vpc_route_tables(session, args.core_network_id)
        
        if route_results:
            results['steps_completed'].append('routes')
            results['route_updates'] = route_results
            
            # Count successes and failures
            successful_updates = len([r for r in route_results if r['status'] == 'Updated'])
            total_updates = len(route_results)
            
            print(f"✓ Route table updates completed: {successful_updates}/{total_updates} successful")
            
            if successful_updates < total_updates:
                failed_updates = total_updates - successful_updates
                results['errors'].append(f"{failed_updates} route table updates failed")
        else:
            results['errors'].append("Route table update failed")
            print("✗ Route table update failed")
            if args.step == 'routes':
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
    
    # Save results to file
    with open('cloudwan_deployment_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: cloudwan_deployment_results.json")


if __name__ == "__main__":
    main()