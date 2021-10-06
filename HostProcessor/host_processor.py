"""Query TimeStream DB and Update WAF Ipsets if Frequency greater than Threshold"""

import time
import os
import datetime
import logging
from typing import Set, Tuple, List, Callable, Dict, Optional, TypedDict, Any
import boto3

logging.basicConfig(
    format='{"logger": "%(name)s", "severity": "%(levelname)s", "line": %(lineno)d, "message": "%(message)s", "function": "%(funcName)s"}',
)

logger = logging.getLogger()
logger.setLevel(int(os.getenv("LOG_LVL", '10')))

TIMESTREAM_DB_NAME = os.environ["TIMESTREAM_DB_NAME"]
TIMESTREAM_TABLE_NAME = os.environ["TIMESTREAM_TABLE_NAME"]
SNS_ARN = os.environ["SNS_ARN"]
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

def save_block_history(host: str, distribution: str, blocked_ip: List[str]) -> None:
    """Inserts Blocked Ip data in dynamodb table"""

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(os.environ['BLOCKLIST_DYNAMODB'])
    # with put_item function we insert data in Table
    table.put_item(
        Item={
            'host': host,
            'distribution': distribution,
            'time': str(datetime.datetime.now()),
            'ip': blocked_ip
        }
    )
    logger.debug("Added %s ip in Dynamo DB table %s", blocked_ip, os.environ['BLOCKLIST_DYNAMODB'])


def update_waf_ipset(ipset_name: str, ipset_id: str, ips_to_be_blocked: Set[str], host: str, distribution: str, ip_type: str) -> List[str]:
    """Add offending ips in waf ip_set"""

    if ip_type == "IPv4":
        ips_to_be_blocked = set(map(lambda x: x+"/32", ips_to_be_blocked))
    else:
        ips_to_be_blocked = set(map(lambda x: x+"/128", ips_to_be_blocked))
    logger.debug("Blocking: %s", str(ips_to_be_blocked))

    # Get LockToken and Existing Address List
    lock_token, existing_ips = get_ipset_lock_token(waf_client, ipset_name, ipset_id)

    # existing_ips.extend(ips_to_be_blocked)
    ips_to_be_blocked.update(existing_ips)  # Removing duplicates
    ips_to_be_blocked_list: List[str] = list(ips_to_be_blocked)
    # existing_ips = list(set(existing_ips)) 

    waf_client.update_ip_set(
        Name=ipset_name,
        Scope='CLOUDFRONT',
        Id=ipset_id,
        Addresses=ips_to_be_blocked_list,
        LockToken=lock_token
    )

    save_block_history(host, distribution, ips_to_be_blocked_list)
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


def process_row(column_info: List[str], row: Dict[str, Any], threshold: int, host: str, distribution: str) -> Tuple[Optional[str], Optional[str]]:
    '''if 'no of request' > 'threshold' then return the ip and type of ip'''

    row_dict = {column["Name"]:value["ScalarValue"] for column, value in zip(column_info, row["Data"])}

    # Check the IP Frequency for the Given Host and Distribution
    if row_dict["cs_host"] == host and row_dict["x_host_header"] == distribution:

        # If Frequency greater than Threshold, return the IP and IP Version
        if int(row_dict["Frequency"]) > threshold:
            logger.debug("Offending Ip %s found in row %s", row_dict["c_ip"], str(row_dict))
            return row_dict["c_ip"], row_dict["c_ip_version"]
    else:
        msg = {
        "Host": {
            "Received": host,
            "TimeStream": row_dict["cs_host"],
            },
        "Distribution": {
            "Received": distribution,
            "Timestream": row_dict["x_host_header"],
            },
        }
        logger.debug("Host, Distribution Does not match: %s", msg)
        return None, None


def process_host(host: str, distribution: str, duration: str, threshold: int, offending_ips: IpDetails) -> IpDetails:
    """Query Timestream db for logs and return ips where count greater than threshold"""

    query_client = boto3.client('timestream-query')
    paginator = query_client.get_paginator('query')

    query: str = f'''SELECT c_ip, cs_host, cs_uri_stem, x_host_header, c_ip_version, COUNT(c_ip) AS Frequency FROM "{TIMESTREAM_DB_NAME}"."{TIMESTREAM_TABLE_NAME}"  WHERE cs_host='{host}' AND time between ago({duration}) and now() GROUP BY c_ip,cs_host,cs_uri_stem,c_ip_version,x_host_header ORDER BY Frequency DESC '''
    logger.info("Query String = %s", query)

    try:
        page_iterator = paginator.paginate(QueryString=query)

        for page in page_iterator:
            column_info = page['ColumnInfo']
            logger.debug("Col: %s", str(column_info))
            for row in page['Rows']:
                logger.debug("Row: %s", str(row))
                ip, version = process_row(column_info, row, threshold, host, distribution)
                if ip:
                    offending_ips[version]["ips"].add(ip)

    except Exception as err:
        logger.exception("ERROR IN TIMESTREAM QUERY")
        logger.info(f"Column_info: {column_info}, Row: {row} Threshold: {threshold}, Host: {host}, Distribution: {distribution}")
        exit(f"Exception while running timestream query: {err}")
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
    logger.debug("Get Configurations details from Dynamo db Successfully")
    return response['Item']['duration'], int(response['Item']['threshold'])

def publish_to_sns(sub, msg):
    topic_arn = SNS_ARN
    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=topic_arn,
        Message=msg,
        Subject=sub
    )

    logger.info("Published to SNS: %s", str(response))

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

    host, distribution = event['host_details'].split(',')

    duration, threshold = get_config(host, distribution)
    logger.info(f"Host: {host}, distribution: {distribution}, duration: {duration}, threshold: {threshold}, from table {os.environ['CONFIGURATION_DYNAMODB']}")

    offending_ips = process_host(host, distribution, duration, threshold, offending_ips_info)
    logger.info(offending_ips)

    for ip_version, ip_details in offending_ips.items():
        if ip_details["ips"]:
            blocked_ips = update_waf_ipset(ip_details["ipset_name"], ip_details["ipset_id"], ip_details["ips"], host, distribution, ip_version)
            logger.info('Blocked Ips: %s', str(blocked_ips))
            logger.info('Updated IPSet %s with %d CIDRs', ip_details["ipset_name"], len(blocked_ips))
        else:
            logger.info("No %s Addresses found", ip_version)

    if offending_ips['IPv4']['ips'] or offending_ips['IPv6']['ips']:
        sub = f"List of IP's Blocked by WAF"
        msg = f"""
            ------------------------------------------------------------------------------------
            Summary of the process:
            ------------------------------------------------------------------------------------
            {'Host':<20}:{host}
            {'Distribution':<20}:{distribution}
            {'Threshold':<20}:{threshold}
            {'Duration':<20}:{duration}
            {'IPV4':<20}:{offending_ips['IPv4']['ips']}
            {'IPV6':<20}:{offending_ips['IPv6']['ips']}
            ------------------------------------------------------------------------------------
            """
        publish_to_sns(sub, msg)