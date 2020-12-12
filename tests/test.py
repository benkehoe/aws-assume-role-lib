import argparse
import dataclasses
import uuid
import json

import boto3
import botocore
from botocore.exceptions import ClientError, ParamValidationError, NoCredentialsError

import aws_assume_role_lib

@dataclasses.dataclass
class Ids:
    RoleArn: str = None
    TopicArn: str = None

def get_ids(session, stack_name):
    cloudformation = session.resource("cloudformation")
    stack = cloudformation.Stack(stack_name)

    fields = [f.name for f in dataclasses.fields(Ids)]
    ids = Ids()
    for output in stack.outputs:
        if output["OutputKey"] in fields:
            setattr(ids, output["OutputKey"], output["OutputValue"])

    print("ids:", ids)

    missing = [f for f in fields if getattr(ids, f) is None]
    if missing:
        raise ValueError("Stack is missing {}".format(", ".join(missing)))

    return ids

def test_assume_role(session, ids):
    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn)

    response = assumed_role_session.client("sts").get_caller_identity()
    assumed_role_arn = response["Arn"]

    assert ids.RoleArn.rsplit("/", 1)[1] == assumed_role_arn.split("/")[1]

    sns = assumed_role_session.client("sns")

    message = "1 {}".format(uuid.uuid4())
    print("Sending message", repr(message))

    sns.publish(TopicArn=ids.TopicArn, Message=message)

def test_assume_role_policy_deny(session, ids):
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "sns:*",
            "Resource": "*"
        }]
    })

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, Policy=policy)

    response = assumed_role_session.client("sts").get_caller_identity()
    assumed_role_arn = response["Arn"]

    assert ids.RoleArn.rsplit("/", 1)[1] == assumed_role_arn.split("/")[1]

    sns = assumed_role_session.client("sns")

    message = "2 {}".format(uuid.uuid4())
    print("Sending message", repr(message))

    try:
        sns.publish(TopicArn=ids.TopicArn, Message=message)
        assert False, "Failed to deny"
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != "AuthorizationError":
            raise

def test_role_session_name(session, ids):
    session_name = str(uuid.uuid4())
    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, RoleSessionName=session_name)

    response = assumed_role_session.client('sts').get_caller_identity()

    assert response["Arn"].split("/")[-1] == session_name

def test_parent_session(session, ids):
    parent_arn_1 = session.client('sts').get_caller_identity()['Arn']

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn)

    parent_arn_2 = assumed_role_session.assume_role_parent_session.client('sts').get_caller_identity()['Arn']

    assert parent_arn_1 == parent_arn_2

def test_invalid_params(session, ids):
    # too short duration
    try:
        aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, DurationSeconds=5)
        assert False, "Failed to raise param validation error"
    except ParamValidationError:
        pass

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, DurationSeconds=5, validate=False)

    try:
        assumed_role_session.client("sts").get_caller_identity()
        assert False, "Failed to raise param validation error"
    except ParamValidationError:
        pass

class EmptyProvider(botocore.credentials.CredentialProvider):
    def load(self):
        return None

def test_no_parent_creds(session, ids):
    botocore_session = botocore.session.Session()
    botocore_session.register_component(
        'credential_provider',
        botocore.credentials.CredentialResolver([EmptyProvider()])
    )

    session = boto3.Session(botocore_session=botocore_session, region_name="us-east-1")

    assert session.get_credentials() is None

    try:
        aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn)
        assert False, "Failed to raise credential validation error"
    except NoCredentialsError:
        pass

    assumed_role_session = aws_assume_role_lib.assume_role(session, ids.RoleArn, validate=False)

    try:
        assumed_role_session.client("sts").get_caller_identity()
        assert False, "Failed to raise error for lack of credentials"
    except AttributeError as e:
        if e.args[0] != "'NoneType' object has no attribute 'get_frozen_credentials'":
            raise

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("stack_name")
    parser.add_argument("--profile")

    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)

    ids = get_ids(session, args.stack_name)

    for name, value in globals().items():
        if name.startswith("test_") and callable(value):
            print("Running", name)
            value(session, ids)

if __name__ == "__main__":
    main()
