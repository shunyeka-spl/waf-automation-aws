# import json
import boto3
import time
# boto3.setup_default_session(profile_name='ssdev-1')
print("Program started")

ipset_name='test-ip-set-name'
ipset_id='5511edd2-e521-4a31-a20b-7cac41be38e1'
 

def update_waf_ipset(ipset_name,ipset_id,ip_to_be_blocked):
    """Updates the AWS WAF IP set"""
    session = boto3.session.Session(profile_name='ssdev-1')
    waf_client = session.client('wafv2',region_name='us-east-1')
    
    # waf_client = boto3.client('wafv2',region_name='us-east-1')

    lock_token = get_ipset_lock_token(waf_client,ipset_name,ipset_id)
    address_list=address_list.append()
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
    print(ip_set)
    
    return ip_set['LockToken']
    
def get_ipset_lock_token(client,ipset_name,ipset_id):
    """Returns the AWS WAF IP set lock token"""
    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id)
    print("Inside get_ipset_lock_token")
    print(ip_set)
    
    return ip_set['LockToken']
    


def isIPv4(IP):
    try:
        return True if type(ip_address(IP)) is IPv4Address else False
    except ValueError:
        return "Invalid"

def query():
    # TODO implement
    # print("QUERY STARTED")
    # boto3.setup_default_session(profile_name='ssdev-1')
    session = boto3.session.Session(profile_name='ssdev-1')
    query_client = session.client('timestream-query')
    paginator = query_client.get_paginator('query')
    
    DATABASE_NAME='CloudFrontLogsTimeSeriesDb-xBECBoapfI2U'
    TABLE_NAME='RealtimeLogsTable-7MYNnsSemTCE'
    DURATION='5s'
    
    # See records ingested into this table so far
    # QUERY = f''''SELECT  c_ip,cs_host,cs_uri_stem,x_host_header, COUNT(c_ip) AS Frequency FROM "{DATABASE_NAME}"."{TABLE_NAME}" WHERE time between ago(15m) and now() GROUP BY c_ip,cs_host,cs_uri_stem,x_host_header ORDER BY Frequency DESC '''
    QUERY = f'''SELECT c_ip, cs_host, cs_uri_stem, x_host_header, COUNT(c_ip) AS Frequency FROM "{DATABASE_NAME}"."{TABLE_NAME}"  WHERE time between ago({DURATION}) and now() GROUP BY c_ip,cs_host,cs_uri_stem,x_host_header ORDER BY Frequency DESC '''
    # QUERY='SELECT * FROM "CloudFrontLogsTimeSeriesDb-xBECBoapfI2U"."RealtimeLogsTable-7MYNnsSemTCE" WHERE time between ago(150m) and now() ORDER BY time DESC LIMIT 10 '
    
    try:
        page_iterator = paginator.paginate(QueryString=QUERY)
        for page in page_iterator:
            # print(type(page))
            # print(page)
            column_info = page['ColumnInfo']
            for row in page['Rows']:
                _parse_row(column_info, row)
                # print('\n')
                
    except Exception as err:
        print("THERE WAS AN ERROR")
        print("Exception while running query:", err)
    
def _parse_row(column_info, row):
    data = row['Data']
    # row_output = []
    # for j in range(len(data)):
    #     info = column_info[j]
        # datum = data[j]
    #     print(info)
    
    print(data[0]['ScalarValue'],' ',data[4]['ScalarValue'])    
    if int(data[4]['ScalarValue'])>30:
        ip_to_be_blocked=data[0]['ScalarValue']
        print('BLOCKing',ip_to_be_blocked,'because it made',data[4]['ScalarValue'],'attempts')
        # if isIPv4(ip_to_be_blocked):
        #     address_list=get_address_list_waf_ipset(ipset_name,ipset_id)
        #     address_list=['10.0.0.2/32']
        #     update_waf_ipset(ipset_name,ipset_id,address_list)
        update_waf_ipset(ipset_name,ipset_id,IP)
        # row_output.append(self._parse_datum(info, datum))

        # return "{%s}" % str(row_output)
def repeat():
    while True:
        print ("tick")
        query()
        time.sleep(2)
repeat()
print("Program Ended")