# import json
import boto3
import time
# boto3.setup_default_session(profile_name='ssdev-1')
print("Program started")

def query():
    # TODO implement
    # print("QUERY STARTED")
    # boto3.setup_default_session(profile_name='ssdev-1')
    session = boto3.session.Session(profile_name='ssdev-1')
    query_client = session.client('timestream-query')
    paginator = query_client.get_paginator('query')
    
    DATABASE_NAME='CloudFrontLogsTimeSeriesDb-xBECBoapfI2U'
    TABLE_NAME='RealtimeLogsTable-7MYNnsSemTCE'
    DURATION='30s'
    
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
        print('You should BLOCK',data[0]['ScalarValue'],'because it made',data[4]['ScalarValue'],'attempts')
        # row_output.append(self._parse_datum(info, datum))

        # return "{%s}" % str(row_output)
def repeat():
    while True:
        print ("tick")
        query()
        time.sleep(25)
repeat()
print("Program Ended")