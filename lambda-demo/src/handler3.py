import os
import boto3
from aws_error_utils import errors

ROLE_ARN    = os.environ['ROLE_ARN']
BUCKET_NAME = os.environ['BUCKET_NAME']
TABLE_NAME  = os.environ['TABLE_NAME']
USE_SOURCE_IDENTITY = os.environ.get('USE_SOURCE_IDENTITY', '').lower() in ['1', 'true']

KEY = 'Function3'

SESSION = boto3.Session()

_STS = SESSION.client('sts')
LAMBDA_ROLE_ARN = _STS.get_caller_identity()['Arn']

if USE_SOURCE_IDENTITY:
    _response = _STS.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        SourceIdentity=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        # DurationSeconds=4*60*60,
    )
else:
    _response = _STS.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName=os.environ['AWS_LAMBDA_FUNCTION_NAME'],
        # DurationSeconds=4*60*60,
    )
_credentials = _response['Credentials']

ASSUMED_ROLE_SESSION = boto3.Session(
    aws_access_key_id=_credentials['AccessKeyId'],
    aws_secret_access_key=_credentials['SecretAccessKey'],
    aws_session_token=_credentials['SessionToken']
)

ASSUMED_ROLE_ARN = ASSUMED_ROLE_SESSION.client('sts').get_caller_identity()['Arn']

S3 = ASSUMED_ROLE_SESSION.client('s3')

DYNAMODB = ASSUMED_ROLE_SESSION.resource('dynamodb')

TABLE = DYNAMODB.Table(TABLE_NAME)

def handler(event, context):
    try:
        response = S3.get_object(
            Bucket=BUCKET_NAME,
            Key=KEY,
        )
        s3_result = response['Body'].read()
    except errors.AccessDenied:
        s3_result = "Access denied!"
    except Exception as e:
        s3_result = str(e)

    try:
        response = TABLE.get_item(
            Key={'pk': KEY},
        )
        ddb_result = response['Item']
    except errors.AccessDeniedException:
        ddb_result = "Access denied!"
    except Exception as e:
        ddb_result = str(e)

    return {
        'lambda_role_arn': LAMBDA_ROLE_ARN,
        'assumed_role_arn': ASSUMED_ROLE_ARN,
        'use_source_identity': USE_SOURCE_IDENTITY,
        's3': s3_result,
        'ddb': ddb_result,
    }
