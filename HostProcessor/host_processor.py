import boto3
import time
import os
import datetime

# test ipset_name and ipset_ip. Later get these in ENV variables during production
ipset_name='test-ip-set-name'
ipset_id='5511edd2-e521-4a31-a20b-7cac41be38e1'
 
# Check if an IP Address is IPv4 or Ipv6
def isIPv4(IP):
    try:
        return True if type(ip_address(IP)) is IPv4Address else False
    except ValueError:
        return "Invalid IP Type"

def save_blocked_ip(CS_HOST,blocked_ip):
    """
    This function inserts data in dynamodb table
    Returns
    -------
    Dictionary
        Response Dictionary
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['BLOCKLIST_DYNAMODB']) 
    #with put_item function we insert data in Table
    response = table.put_item(
        Item = {
               'cs_host': CS_HOST,
               'time': str(datetime.datetime.now()),
               'ip':blocked_ip
               } 
        )

# method 'update_waf_ipset' adds IP to ip_set
def update_waf_ipset(ipset_name,ipset_id,ip_to_be_blocked,CS_HOST):
    print("Blocking",ip_to_be_blocked)
    ip_to_be_blocked=ip_to_be_blocked+"/32"
    
    # Do not remove 'us-east-1'. All WAF CloudFront aka GLOBAL is by default 'us-east-1' and cannot be changed
    waf_client = boto3.client('wafv2',region_name='us-east-1')
    
    # Get LockToken and Existing Address List
    lock_token, address_list = get_ipset_lock_token(waf_client,ipset_name,ipset_id)
    # Add IP to be blocked to address_list
    address_list.append(ip_to_be_blocked)
    print("address_list = ",address_list)
    # update WAF IpSet
    waf_client.update_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id,
        Addresses=address_list,
        LockToken=lock_token
    )
    print('Blocked',ip_to_be_blocked,'Successfully')
    save_blocked_ip(CS_HOST,ip_to_be_blocked)

    print(f'Updated IPSet "{ipset_name}" with {len(address_list)} CIDRs')

# Method  'get_ipset_lock_token' returns LockToken and Existing Address List
def get_ipset_lock_token(client,ipset_name,ipset_id):
    """Returns the AWS WAF IP set lock token"""
    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id)
    print("Inside get_ipset_lock_token")
    # print("ip_set",ip_set)
    return ip_set['LockToken'],ip_set['IPSet']['Addresses']
    
def _parse_row(column_info, row,CS_HOST):
    data = row['Data']
    print(data[0]['ScalarValue'],' ',data[4]['ScalarValue'])    
    
    '''if no of request is greater than > 'X' then block the IP
    aka add the IP to WAF IPSet '''
    print("IP:",data[0]['ScalarValue'])
    print(data[4]['ScalarValue'])
    if int(data[4]['ScalarValue'])>30:
        ip_to_be_blocked=data[0]['ScalarValue']
        print('BLOCKing',ip_to_be_blocked,'because it made',data[4]['ScalarValue'],'attempts')
        update_waf_ipset(ipset_name,ipset_id,ip_to_be_blocked,CS_HOST)

def query(CS_HOST,DURATION):
    query_client = boto3.client('timestream-query')
    paginator = query_client.get_paginator('query')
    
    DATABASE_NAME='CloudFrontLogsTimeSeriesDb-xBECBoapfI2U'
    TABLE_NAME='RealtimeLogsTable-7MYNnsSemTCE'
    # DURATION='15s'
    
    # Query String
    ''' Query String gets count/frequency of requests made by each IP for each cloudfront url'''
    QUERY = f'''SELECT c_ip, cs_host, cs_uri_stem, x_host_header, COUNT(c_ip) AS Frequency FROM "{DATABASE_NAME}"."{TABLE_NAME}"  WHERE cs_host='{CS_HOST}' AND time between ago({DURATION}) and now() GROUP BY c_ip,cs_host,cs_uri_stem,x_host_header ORDER BY Frequency DESC '''
    print("Query String =",QUERY)
    try:
        '''page_iterator accepts Query response as Pages
        Iterate through each Page then
        Iterate through each Row
        Each row values returned by each row of Query'''
        page_iterator = paginator.paginate(QueryString=QUERY)
        for page in page_iterator:
            column_info = page['ColumnInfo']
            for row in page['Rows']:
                print("Printing row")
                print(page)
                _parse_row(column_info, row,CS_HOST)
    except Exception as err:
        print("THERE WAS AN ERROR")
        print("Exception while running query:", err)
        

def get_config(cs_host):
    """
    This function reads configuration data from dynamodb table
    Returns
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['CONFIGURATION_DYNAMODB'])
    #with Get_item function we get the data
    response = table.get_item(
        Key = {
              "address" : cs_host
              }
        )
    return response['Item']['sleep'], response['Item']['query_time']

def lambda_handler(event, context):
    cs_host=event['cs_host']
    sleep, query_time = get_config(cs_host)
    
    print("Sleep for",sleep,'seconds')
    print('Query for',query_time)
    
    time.sleep(sleep)
    
    print("Hello Lambda")
    print("Printing event")
    print(event)
    
    query(cs_host,query_time)
    