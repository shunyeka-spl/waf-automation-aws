import boto3
import json
import decimal

# Generating a resources from the default session
session = boto3.session.Session(profile_name='ssdev-1')
dynamodb = session.resource('dynamodb')

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
    
print(insert_data())

