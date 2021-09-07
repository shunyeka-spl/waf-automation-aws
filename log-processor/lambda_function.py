import base64
import json
import boto3
from botocore.config import Config
import os
import datetime
import urllib.parse

session = boto3.Session()

# Recommended Timestream write client SDK configuration:
#  - Set SDK retry count to 10.
#  - Use SDK DEFAULT_BACKOFF_STRATEGY
#  - Set RequestTimeout to 20 seconds .
#  - Set max connections to 5000 or higher.
timestream_write = session.client('timestream-write', config=Config(read_timeout=20, max_pool_connections=5000, retries={'max_attempts': 10}))
# TABLE_NAME from CloudFormation is set in format of DATABASE|TABLE, so we need to split it
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-timestream-table.html
TABLE_NAME_CF= os.environ['TABLE_NAME']
fields = TABLE_NAME_CF.split('|')
DATABASE_NAME = fields[0]
TABLE_NAME = fields[1]
lambda_client = boto3.client('lambda')

# Loads a json configuration object that defines the data type mappings for each of the valid values of Realtime Log Fields
FIELD_DATA_MAPPINGS = {}
with open('./config/cf_realtime_log_field_mappings.json') as f:
    data = json.load(f)
    FIELD_DATA_MAPPINGS = data['cf_realtime_log_fields']
    # Debug
    #print('Configured field data type mappings: ', json.dumps(FIELD_DATA_MAPPINGS))

def invoke_host_processor(host_details):
        payload = {}
        payload['host_details'] = host_details

        lambda_client.invoke(FunctionName='HostProcessor',
                InvocationType='Event',
                Payload=json.dumps(payload))

# Utility function for parsing the header fields
def parse_headers(headers, header_type):
    supported_types = ['cs-headers', 'cs-header-names']
    output = []
    if header_type not in supported_types:
        print('Could not parse header, invalid type: {}'.format(header_type))

    if header_type == 'cs-headers':
        header_list = list(filter(None, urllib.parse.unquote(headers).split('\n'))) # filter out empty strings
        for header in header_list:
            kv_pair = header.split(':', 1)
            if len(kv_pair) > 1:
                for i in range(0, len(kv_pair), 2):
                    output.append({
                        'Name': kv_pair[i],
                        'Value': kv_pair[i + 1]
                    })
    if header_type == 'cs-header-names':
        output = list(filter(None, urllib.parse.unquote(headers).split('\n')))
    return output

def write_batch_timestream(records, record_counter):
    print("Printing records")
    print(records)
    print("Printing record_counter",record_counter)
    # print()
    try:
        result = timestream_write.write_records(DatabaseName = DATABASE_NAME, TableName = TABLE_NAME, Records = records, CommonAttributes = {})
        print('Processed [%d] records. WriteRecords Status: [%s]' % (record_counter, result['ResponseMetadata']['HTTPStatusCode']))

    except Exception as e:
        # print(records)
        print(e)
        raise Exception('There was an error writing records to Amazon Timestream when inserting records')
        

def lambda_handler(event, context):
    
    records = []
    record_counter = 0
    print("Printing Events")
    print(event)
    unique_cs_hosts=set()
 
    for record in event['Records']:
    
        # Extracting the record data in bytes and base64 decoding it
        payload_in_bytes = base64.b64decode(record['kinesis']['data'])
        print("Printing payload_in_bytes")
        print(payload_in_bytes)
        # Converting the bytes payload to string
        payload = "".join(map(chr, payload_in_bytes))
        print("Printing payload")
        print(payload) 
        # dictionary where all the field and record value pairing will end up
        payload_dict = {}
        
        # counter to iterate over the record fields
        counter = 0
        
        # generate list from the tab-delimited log entry
        payload_list = payload.strip().split('\t')
        
        # Use field mappings configuration to perform data type conversion as needed
        for field, data_type in FIELD_DATA_MAPPINGS.items():
            if(payload_list[counter].strip() == '-'):
                data_type = "str"
            if(data_type == "int"):
                payload_dict[field] = int(payload_list[counter].strip())
            elif(data_type == "float"):
                payload_dict[field] = float(payload_list[counter].strip())
            else:
                payload_dict[field] = payload_list[counter].strip()
            counter = counter + 1
        
        # Parse the headers and return as lists. This is useful if you want to log the header information as well
        if('cs-headers' in payload_dict.keys()):
            del payload_dict['cs-headers'] # remove this line and uncomment below to include cs-headers as a list in the record
            #payload_dict['cs-headers'] = parse_headers(payload_dict['cs-headers'], 'cs-headers')
        if('cs-header-names' in payload_dict.keys()):
            del payload_dict['cs-header-names'] # remove this line and uncomment below to include cs-header-names as a list
            #payload_dict['cs-header-names'] = parse_headers(payload_dict['cs-header-names'], 'cs-header-names')

        dimensions_list = []        
        for field, value in payload_dict.items():
            field_name = field.replace('-','_') # replace dashes in field names with underscore to adhere to Timsestream requirements                        
            
            dimensions_list.append(
                { 'Name': field_name, 'Value': str(value) }
            )   
        print(payload_dict)
        host_details = f"{payload_dict['cs-host']},{payload_dict['x-host-header']}"
        unique_cs_hosts.add(host_details)


        record = {
            'Dimensions': dimensions_list,
            'MeasureName': 'sc_bytes',
            'MeasureValue': str(payload_dict['sc-bytes']),
            'MeasureValueType': 'BIGINT',
            'Time': str(int(payload_dict['timestamp'])),
            'TimeUnit': 'SECONDS'
        }
        records.append(record)
        print("Printing record inside handler")
        print(record)
        record_counter = record_counter + 1

        if(len(records) == 100): 
            write_batch_timestream(records, record_counter)
            records = []

    if(len(records) != 0):
        write_batch_timestream(records, record_counter)
    
    for host_details in unique_cs_hosts:
        print("Invoke Host Processor",host_details)
        invoke_host_processor(host_details)
    
    

    print('Successfully processed {} records.'.format(len(event['Records'])))