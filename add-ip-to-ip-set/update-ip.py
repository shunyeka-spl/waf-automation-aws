import boto3
from ipaddress import ip_address, IPv4Address
 
ipset_name='test-ip-set-name'
ipset_id='5511edd2-e521-4a31-a20b-7cac41be38e1'
ip_to_be_blocked='10.0.0.3/32'

def isIPv4(IP):
    try:
        return True if type(ip_address(IP)) is IPv4Address else False
    except ValueError:
        return "Invalid"

def update_waf_ipset(ipset_name,ipset_id,ip_to_be_blocked):
    """Updates the AWS WAF IP set"""
    session = boto3.session.Session(profile_name='ssdev-1')
    waf_client = session.client('wafv2',region_name='us-east-1')
    
    # waf_client = boto3.client('wafv2',region_name='us-east-1')

    lock_token,address_list = get_ipset_lock_token(waf_client,ipset_name,ipset_id)
    # address_list = get_ipset_list(waf_client,ipset_name,ipset_id)
    address_list.append(ip_to_be_blocked)
    print("\n\n",address_list,"\n\n")
    waf_client.update_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id,
        Addresses=address_list,
        LockToken=lock_token
    )

    print(f'Updated IPSet "{ipset_name}" with {len(address_list)} CIDRs')

def get_ipset_lock_token(client,ipset_name,ipset_id):
    """Returns the AWS WAF IP set lock token"""
    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id)
    print("Inside get_ipset_lock_token")
    # print(ip_set)
    # print(type(ip_set['IPSet']['Addresses']))
    
    return ip_set['LockToken'],ip_set['IPSet']['Addresses']
# def get_ipset_list(client,ipset_name,ipset_id):
#     """Returns the AWS WAF IP set lock token"""
#     ip_set = client.get_ip_set(
#         Name=ipset_name,
#         Scope='CLOUDFRONT',
#         Id=ipset_id)
#     print("Inside get_ipset_list")
#     # print(ip_set)
#     print(type(ip_set['IPSet']['Addresses']))
#     print(ip_set['IPSet']['Addresses'])
    
#     return ip_set['IPSet']['Addresses']
    

update_waf_ipset(ipset_name,ipset_id,ip_to_be_blocked)