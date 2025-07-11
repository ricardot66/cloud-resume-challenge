import json
import boto3
import os
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb')
    
    # Table name from environment variable (best practice)
    table_name = os.environ.get('DYNAMODB_TABLE', 'VisitorCounter')
    table = dynamodb.Table(table_name)
    
    try:
        # Atomic counter update using UpdateItem
        response = table.update_item(
            Key={'id': 'visitors'},
            UpdateExpression='ADD #count :incr',
            ExpressionAttributeNames={
                '#count': 'count'
            },
            ExpressionAttributeValues={
                ':incr': 1
            },
            ReturnValues='UPDATED_NEW'
        )
        
        # Extract and return the new count
        updated_count = response.get('Attributes', {}).get('count', 0)
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',  # Replace * with your domain for security
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': json.dumps({
                'count': int(updated_count)
            })
        }
        
    except ClientError as e:
        print(f"Error updating visitor count: {e}")
        
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            'body': json.dumps({
                'error': 'Failed to update visitor count'
            })
        }