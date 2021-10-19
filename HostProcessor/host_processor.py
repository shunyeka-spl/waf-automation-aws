"""Query TimeStream DB and Update WAF Ipsets if Frequency greater than Threshold"""

import os
import datetime
import logging
import traceback
import concurrent.futures
from typing import Set, Tuple, List, Callable, Dict, Optional, TypedDict, Any, Union
import boto3

logging.basicConfig(
    format='{"logger": "%(name)s", "severity": "%(levelname)s", "line": %(lineno)d, "message": "%(message)s", "function": "%(funcName)s"}',
)

logger = logging.getLogger()
logger.setLevel(int(os.getenv("LOG_LVL", '10')))

WAF_BLOCK_IP_TABLE = os.environ['BLOCKLIST_DYNAMODB']
WAF_DDB_CONFIG_TABLE = os.environ['CONFIGURATION_DYNAMODB']

SNS_ARN = os.environ["SNS_ARN"]
THREAD_COUNT = int(os.environ['THREAD_COUNT'])

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

class HostDetails(TypedDict):
    duration: str
    threshold: int
    host: str
    distribution: str

# WAF V2 CloudFront is only supported in Region 'us-east-1' and Thus, cannot be changed
waf_client = boto3.client('wafv2', region_name='us-east-1')

def remove_unwanted_ip(ips: List[str]) -> List[str]:
    """Remove Private ips added while creating IPSET by cloudformation"""
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
    return ips

def save_block_history(host_config: HostDetails, blocked_ips: List[str], ip_type: str, ipset_id: str, ipset_name: str) -> None:
    """Inserts Blocked Ip data in dynamodb table"""

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(WAF_BLOCK_IP_TABLE)

    for ip in blocked_ips:
        values = {
            **host_config,
            'time': str(datetime.datetime.now()),
            'ip': ip,
            'ip_type': ip_type,
            'ipset_id': ipset_id,
            'ipset_name': ipset_name,
        }
        response = table.get_item(
            Key={
                'ip': ip,
                'distribution': host_config['distribution'],
            },
        )
        if not response.get('Item'):
            logger.debug(f"Put block ip to DDB table {WAF_BLOCK_IP_TABLE} data: {values}")
            table.put_item(
                Item=values
            )
            publish_to_sns(host_config, ip, ip_type)
    logger.debug("Added %s ip in Dynamo DB table %s", blocked_ips, WAF_BLOCK_IP_TABLE)


def update_waf_ipset(ipset_name: str, ipset_id: str, ips_to_be_blocked: Set[str], host_config: HostDetails, ip_type: str, retry: int = 3) -> Tuple[List[str], str]:
    """Add offending ips in waf ip_set"""

    if ip_type == "IPv4":
        ips_to_be_blocked = set(map(lambda x: x+"/32", ips_to_be_blocked))
        copy_block_ips = ips_to_be_blocked.copy()
    else:
        ips_to_be_blocked = set(map(lambda x: x+"/128", ips_to_be_blocked))
        copy_block_ips = ips_to_be_blocked.copy()

    # Get LockToken and Existing Address List
    lock_token, existing_ips = get_ipset_lock_token(waf_client, ipset_name, ipset_id)

    ips_to_be_blocked.update(existing_ips)  # Removing duplicates
    ips_to_be_blocked_list: List[str] = list(ips_to_be_blocked)

    remove_unwanted_ip(ips_to_be_blocked_list)
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
        logger.exception(e)
        if retry > 0:
            logger.info("Retrying Function Update Waf IpSet: %d", retry)
            return update_waf_ipset(ipset_name, ipset_id, ips_to_be_blocked, host_config, ip_type, retry=retry-1)
        else:
            logger.error("Retied %d times, IpSet not Updated", retry)
            raise Exception("Unable to Update Waf IpSet %s, retries: %d exceeded", ipset_name, retry)

    save_block_history(host_config, copy_block_ips, ip_type, ipset_id, ipset_name)
    logger.debug("Added Offending Ip Addresses to WAF IPSets")
    return copy_block_ips, ip_type

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
    try:
        row_dict = {column["Name"]:value["ScalarValue"] for column, value in zip(column_info, row["Data"])}

        if int(row_dict["Frequency"]) > threshold:
            logger.debug("Row debug: %s", str(row_dict))

            if row_dict.get('c_ip'):
                return row_dict["c_ip"], row_dict["c_ip_version"]
            elif row_dict.get('x_forwarded_for'):
                return [i.strip() for i in row_dict["x_forwarded_for"].split(",")], row_dict["c_ip_version"]
            else:
                raise Exception(f"No ip found, frequency > threshold, Row: {row_dict}")
        else:
            return None, None
    except Exception as e:
        logger.exception(f"Error in process_row function: {e}")
        return None, None

def process_host(header: str, host: str, duration: str, threshold: int, offending_ips: IpDetails) -> IpDetails:
    """Query Timestream db for logs and return ips where count greater than threshold"""

    query_client = boto3.client('timestream-query')
    paginator = query_client.get_paginator('query')

    query = f'''SELECT {header}, cs_host, cs_uri_stem, x_host_header, c_ip_version, COUNT({header}) AS Frequency FROM "{TIMESTREAM_DB_NAME}"."{TIMESTREAM_TABLE_NAME}"  WHERE cs_host='{host}' AND time between ago({duration}) and now() AND {header} != '-' GROUP BY {header},cs_host,cs_uri_stem,c_ip_version,x_host_header ORDER BY Frequency DESC '''
    logger.debug("Query String = %s", query)

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
        logger.exception("ERROR IN TIMESTREAM QUERY") # Column_info: {column_info}, Row: {row} Threshold: {threshold}, Host: {host}")
        traceback.print_exc()
        raise
    else:
        # logger.info("TimeStream Query Success")
        return offending_ips

# def publish_to_sns(host: str, distribution: str, threshold: int, duration: str, offending_ips: IpDetails) -> None:
def publish_to_sns(host_config: HostDetails, ip: str, ip_version: str) -> None:
    """Publish Blocked ip details to sns"""

    subject = f"Successfully Blocked a IP"
    message = f"""
        ------------------------------------------
        IP Blocked by WAF
        ------------------------------------------
        {ip_version:<20}    :{ip}
        {'Host':<20}        :{host_config['host']}
        {'Distribution':<20}:{host_config['distribution']}
        {'Threshold':<20}   :{host_config['threshold']}
        {'Duration':<20}    :{host_config['duration']}
        ------------------------------------------
        """

    sns = boto3.client("sns")
    response = sns.publish(
        TopicArn=SNS_ARN,
        Message=message,
        Subject=subject,
    )

    logger.info("Published to SNS: %s", str(response))

def get_config(host: str, distribution: str) -> Tuple[str, int]:
    """This function reads configuration data from dynamodb table"""

    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(WAF_DDB_CONFIG_TABLE)

    response = table.get_item(
        Key={
            "distribution": distribution,
            "host": host
        }
    )
    logger.debug(f"Configurations details from Dynamo db: {response}")
    return response['Item']['duration'], int(response['Item']['threshold'])

def check_ip(ips: Set[str], ip_version: str) -> bool:
    """check offending ip is found or not"""
    if ips:
        logger.info("Found %d new %s Addresses", len(ips), ip_version)
        return True
    else:
        logger.info("No %s Addresses found", ip_version)
        return False

def lambda_handler(event: str, context) -> None:
    """Main Fn: Adds offending ips to WAf Block List based on threshold"""

    logger.debug(event)

    retry: int = 3
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
    host_config: HostDetails = {
        "duration": duration,
        "threshold": threshold,
        "host": host,
        "distribution": distribution,
    }
    logger.info(f"{host_config} from table {WAF_DDB_CONFIG_TABLE}")

    headers = ("x_forwarded_for", "c_ip")
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_project = {executor.submit(process_host, header, host, duration, threshold, offending_ips_info): header for header in headers}
        for future in concurrent.futures.as_completed(future_to_project):
            processed = future_to_project[future]
            try:
                data = future.result()
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("%r generated an exception: %s", processed, exc)
                traceback.print_exc()
                raise 
            else:
                logger.info("%s query status  %s", processed, data)

    logger.info(f"offending_ips_info: {offending_ips_info}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        future_to_project = {executor.submit(update_waf_ipset, ip_details["ipset_name"], ip_details["ipset_id"], ip_details["ips"], host_config, ip_version, retry): (ip_version, ip_details) for ip_version, ip_details in offending_ips_info.items() if check_ip(ip_details["ips"], ip_version)}
        for future in concurrent.futures.as_completed(future_to_project):
            processed = future_to_project[future]
            try:
                data = future.result()
            except Exception as exc: # pylint: disable=broad-except
                logger.error("%r generated an exception: %s", processed, exc)
                traceback.print_exc()
                raise
            else:
                logger.debug("%r status  %s", processed, data)
                # logger.info("Updated IPSet %s with %d IP's", ip_details["ipset_name"], len(data))
                logger.info('Blocked Ips: %s', str(data))

