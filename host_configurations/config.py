# import boto3 module
import boto3
import json
import decimal
import time

# Generating a resources from the default session
session = boto3.session.Session(profile_name='ssdev-1')
dynamodb = session.resource('dynamodb')
sleep=decimal.Decimal(2.5)
time.sleep(sleep)
# print(type(a))

def insert_data():
    """
    This function inserts data in dynamodb table
    Returns
    -------
    Dictionary
        Response Dictionary
    """
    table = dynamodb.Table('TestConfigurationFiles') 
    #with put_item function we insert data in Table
    response = table.put_item(
        Item = {
               'address': 'www.x.com',
               'query_for': '15s',
               'delay':'2s'  
               } 
        )
    return response
    
def get_data():
    """
    This function reads data from dynamodb table
    Returns
    -------
    
        Response Dictionary
    """
    table = dynamodb.Table('TestConfigurationFiles')
    #with Get_item function we get the data
    response = table.get_item(
        Key = {
              "address" : "d1sq1bazt84inb.cloudfront.net"
              }
        )
    
    # response = table.scan()  # Download Dynamodb Table Contents
    # json_object = json.dumps(response["Item"], indent=4)
    print(response['Item']['sleep'])
    print(type(response['Item']['sleep']))
    return response['Item']

print(get_data())
# print(insert_data())

