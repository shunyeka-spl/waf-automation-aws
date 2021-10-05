"""Query TimeStream DB and Update WAF Ipsets if Frequency greater than Threshold"""

import time
import os
import datetime
import logging
from typing import Set, Tuple, List, Callable, Dict, Optional, TypedDict, Any, Union
import boto3

logging.basicConfig(
    format='{"logger": "%(name)s", "severity": "%(levelname)s", "line": %(lineno)d, "message": "%(message)s", "function": "%(funcName)s"}',
)

logger = logging.getLogger()
logger.setLevel(int(os.getenv("LOG_LVL", '10')))

WAF_BLOCK_IP_TABLE = os.environ['BLOCKLIST_DYNAMODB']

TIMESTREAM_DB_NAME = os.environ["TIMESTREAM_DB_NAME"]
TIMESTREAM_TABLE_NAME = os.environ["TIMESTREAM_TABLE_NAME"]

IPV4SET_NAME, IPV4SET_ID, _ = os.environ['IPV4SET_DETAILS'].split("|")
IPV6SET_NAME, IPV6SET_ID, _ = os.environ['IPV6SET_DETAILS'].split("|")

class IPv4Hints(TypedDict):
    ips: Set[str]
    ipset_name: str
    ipset_id: str

class IPv6Hints(TypedDict):
    ips: Set[str]
    ipset_name: str
    ipset_id: str

class IpDetails(TypedDict):
    IPv4: IPv4Hints
    IPv6: IPv6Hints

# WAF V2 CloudFront is only supported in Region 'us-east-1' and Thus, cannot be changed
waf_client = boto3.client('wafv2', region_name='us-east-1')

def remove_unwanted_ip(ips: List[str]) -> List[str]:
    try:
        ips.remove('10.0.0.0/32')
        return ips
    except ValueError as e:
        logger.debug(e)
    try:
        ips.remove('fd4b:9821:be17:8c1e:0000:0000:0000:0000/128')
        return ips
    except ValueError as r:
        logger.debug(r)

def save_block_history(host: str, distribution: str, blocked_ips: List[str], ip_type: str, ipset_id: str, ipset_name: str) -> None:
    """Inserts Blocked Ip data in dynamodb table"""

    remove_unwanted_ip(blocked_ips)

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(WAF_BLOCK_IP_TABLE)
    # with put_item function we insert data in Table

    with table.batch_writer(overwrite_by_pkeys=["distribution", "host"]) as batch:
        for ip in blocked_ips:
            values = {
                    'host': host,
                    'distribution': distribution,
                    'time': str(datetime.datetime.now()),
                    'ip': ip,
                    'ip_type': ip_type,
                    'ipset_id': ipset_id,
                    'ipset_name': ipset_name,
                }
            logger.debug(f"Dynamodb table {WAF_BLOCK_IP_TABLE} data: {values}")
            batch.put_item(
                Item=values
            )
    logger.debug("Added %s ip in Dynamo DB table %s", blocked_ips, WAF_BLOCK_IP_TABLE)


def update_waf_ipset(ipset_name: str, ipset_id: str, ips_to_be_blocked: Set[str], host: str, distribution: str, ip_type: str, retry: int =3) -> List[str]:
    """Add offending ips in waf ip_set"""

    if ip_type == "IPv4":
        ips_to_be_blocked = set(map(lambda x: x+"/32", ips_to_be_blocked))
    else:
        ips_to_be_blocked = set(map(lambda x: x+"/128", ips_to_be_blocked))

    # Get LockToken and Existing Address List
    lock_token, existing_ips = get_ipset_lock_token(waf_client, ipset_name, ipset_id)

    ips_to_be_blocked.update(existing_ips)  # Removing duplicates
    ips_to_be_blocked_list: List[str] = list(ips_to_be_blocked)
    logger.debug("Blocking: %s", str(ips_to_be_blocked_list))

    try:
        waf_client.update_ip_set(
            Name=ipset_name,
            Scope='CLOUDFRONT',
            Id=ipset_id,
            Addresses=ips_to_be_blocked_list,
            LockToken=lock_token
        )
    except waf_client.exceptions.WAFOptimisticLockException as e:
        logger.error(e)
        if retry > 0:
            logger.debug("Retrying Update Waf IpSet: %d", retry)
            return update_waf_ipset(ipset_name, ipset_id, ips_to_be_blocked, host, distribution, ip_type, retry = retry - 1)
        else:
            logger.error("Retied %d times, IpSet not Updated", retry)
            raise Exception("Unable to Update Waf IpSet %s, retries: %d", ipset_name, retry)

    save_block_history(host, distribution, ips_to_be_blocked_list, ip_type, ipset_id, ipset_name)
    logger.debug("Added Offending Ip Addresses to WAF IPSets")
    return ips_to_be_blocked_list

def get_ipset_lock_token(client: Callable, ipset_name: str, ipset_id: str) -> Tuple[str, List[str]]:
    """Returns WAF ip_set  lock token and ips in ipset"""

    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id,
    )
    logger.debug(f"get_ipset json: {ip_set}")
    return ip_set['LockToken'], ip_set['IPSet']['Addresses']


def process_row(column_info: List[str], row: Dict[str, Any], threshold: int) -> Tuple[Optional[Union[str, List[str]]], Optional[str]]:
    '''if 'no of request' > 'threshold' then return the ip and type of ip'''

    row_dict = {column["Name"]:value["ScalarValue"] for column, value in zip(column_info, row["Data"])}

    if int(row_dict["Frequency"]) > threshold:
        logger.debug("Offending Ip %s found in row %s", row_dict["c_ip"], str(row_dict))

        if row_dict.get('c_ip'):
            return row_dict["c_ip"], row_dict["c_ip_version"]
        elif isinstance(row_dict.get('x_forwarded_for'), str):
            return row_dict["x_forwarded_for"], row_dict["c_ip_version"]
        elif isinstance(row_dict.get('x_forwarded_for'), list):
            return [i.strip() for i in row_dict["x_forwarded_for"].split(",")], row_dict["c_ip_version"]
    return None, None

def process_host(header: str, host: str, duration: str, threshold: int, offending_ips: IpDetails) -> IpDetails:
    """Query Timestream db for logs and return ips where count greater than threshold"""

    query_client = boto3.client('timestream-query')
    paginator = query_client.get_paginator('query')

    query = f'''SELECT {header}, cs_host, cs_uri_stem, x_host_header, c_ip_version, COUNT({header}) AS Frequency FROM "{TIMESTREAM_DB_NAME}"."{TIMESTREAM_TABLE_NAME}"  WHERE cs_host='{host}' AND time between ago({duration}) and now() AND {header} != '-' GROUP BY {header},cs_host,cs_uri_stem,c_ip_version,x_host_header ORDER BY Frequency DESC '''
    logger.info("Query String = %s", query)

    try:
        page_iterator = paginator.paginate(QueryString=query)

        for page in page_iterator:
            column_info = page['ColumnInfo']
            for row in page['Rows']:
                logger.debug("Row %s", str(row))
                ip, version = process_row(column_info, row, threshold)
                if isinstance(ip, str):
                    offending_ips[version]["ips"].add(ip)
                elif isinstance(ip, list):
                    offending_ips[version]["ips"].update(ip)

    except Exception as err:
        logger.exception("ERROR IN TIMESTREAM QUERY")
        raise Exception(f"Exception while running query: {err}")
    else:
        logger.info("TimeStream Query Success")
        return offending_ips

def get_config(host: str, distribution: str) -> Tuple[str, int]:
    """This function reads configuration data from dynamodb table"""

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['CONFIGURATION_DYNAMODB'])

    response = table.get_item(
        Key={
            "distribution": distribution,
            "host": host
        }
    )
    logger.debug(f"Configurations details from Dynamo db: {response}")
    return response['Item']['duration'], int(response['Item']['threshold'])


def lambda_handler(event: str, context) -> None:
    """Main Fn: Adds offending ips to WAf Block List based on threshold"""

    logger.info(event)

    offending_ips_info: IpDetails = {
        "IPv4": {
            "ips": set(),
            "ipset_name": IPV4SET_NAME,
            "ipset_id": IPV4SET_ID,
        },
        "IPv6": {
            "ips": set(),
            "ipset_name": IPV6SET_NAME,
            "ipset_id": IPV6SET_ID,
        }
    }
    retry: int = 3

    host, distribution = event['host_details'].split(',')

    duration, threshold = get_config(host, distribution)
    logger.info(f"Host: {host}, distribution: {distribution}, duration: {duration}, threshold: {threshold}, from table {os.environ['CONFIGURATION_DYNAMODB']}")

    headers = ("x_forwarded_for", "c_ip")
    for header in headers:
        offending_ips = process_host(header, host, duration, threshold, offending_ips_info)
        logger.info(offending_ips)

    for ip_version, ip_details in offending_ips.items():
        if ip_details["ips"]:
            blocked_ips = update_waf_ipset(ip_details["ipset_name"], ip_details["ipset_id"], ip_details["ips"], host, distribution, ip_version, retry)
            logger.info('Blocked Ips: %s', str(blocked_ips))
            logger.info("Updated IPSet %s with %d IP's", ip_details["ipset_name"], len(blocked_ips))
        else:
            logger.info("No %s Addresses found", ip_version)

"""
Query for x_forwarded_for column
SELECT x_forwarded_for, cs_host, cs_uri_stem, x_host_header, c_ip_version, COUNT(x_forwarded_for) AS Frequency FROM "CloudFrontLogsTimeSeriesDb-iV8XeSLItCX2"."RealtimeLogsTable-CfP66didm9mb"  WHERE cs_host='waftest1.ccrt.us' AND time between ago(2h) and now() AND x_forwarded_for != '-' GROUP BY x_forwarded_for, cs_host,cs_uri_stem,c_ip_version,x_host_header ORDER BY Frequency DESC

Query for c_ip column , same as above
SELECT c_ip, cs_host, cs_uri_stem, x_host_header, c_ip_version, COUNT(c_ip) AS Frequency FROM "CloudFrontLogsTimeSeriesDb-iV8XeSLItCX2"."RealtimeLogsTable-CfP66didm9mb"  WHERE cs_host='waftest1.ccrt.us' AND time between ago(2h) and now() AND c_ip != '-' GROUP BY c_ip,cs_host,cs_uri_stem,c_ip_version,x_host_header ORDER BY Frequency DESC
"""
