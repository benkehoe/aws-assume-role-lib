import os
import boto3
from aws_error_utils import errors

ROLE_ARN    = os.environ['ROLE_ARN']
BUCKET_NAME = os.environ['BUCKET_NAME']
TABLE_NAME  = os.environ['TABLE_NAME']
USE_SOURCE_IDENTITY = os.environ.get('USE_SOURCE_IDENTITY', '').lower() in ['1', 'true']

KEY = 'Function2'

def handler(event, context):
    session = boto3.Session()

    sts = session.client('sts')
    lambda_role_arn = sts.get_caller_identity()['Arn']

    if USE_SOURCE_IDENTITY:
        response = sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
            SourceIdentity=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        )
    else:
        response = sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        )
    credentials = response['Credentials']

    assumed_role_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    assumed_role_arn = assumed_role_session.client('sts').get_caller_identity()['Arn']

    s3 = assumed_role_session.client('s3')

    try:
        response = s3.get_object(
            Bucket=BUCKET_NAME,
            Key=KEY,
        )
        s3_result = response['Body'].read()
    except errors.AccessDenied:
        s3_result = "Access denied!"
    except Exception as e:
        s3_result = str(e)

    dynamodb = assumed_role_session.resource('dynamodb')
    table = dynamodb.Table(TABLE_NAME)

    try:
        response = table.get_item(
            Key={'pk': KEY},
        )
        ddb_result = response['Item']
    except errors.AccessDeniedException:
        ddb_result = "Access denied!"
    except Exception as e:
        ddb_result = str(e)

    return {
        'lambda_role_arn': lambda_role_arn,
        'assumed_role_arn': assumed_role_arn,
        'use_source_identity': USE_SOURCE_IDENTITY,
        's3': s3_result,
        'ddb': ddb_result,
    }
