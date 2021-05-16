import argparse
import uuid
import json
import tempfile
import os
import datetime
from pathlib import Path
from collections import namedtuple

import boto3
import botocore
from botocore.exceptions import ClientError, ParamValidationError, NoCredentialsError

import aws_assume_role_lib
aws_assume_role_lib.patch_boto3()

Ids = namedtuple("Ids", ["RoleArn", "TopicArn"])

def get_ids(session, stack_name):
    cloudformation = session.resource("cloudformation")
    stack = cloudformation.Stack(stack_name)

    fields = Ids._fields
    data = {}
    for output in stack.outputs:
        if output["OutputKey"] in fields:
            data[output["OutputKey"]] = output["OutputValue"]
    ids = Ids(**data)

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
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "sns:*",
            "Resource": "*"
        }]
    }

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

def test_session_duration(session, ids):
    duration = datetime.timedelta(minutes=15)
    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, DurationSeconds=duration)

    response = assumed_role_session.client('sts').get_caller_identity()

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

    try:
        aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, validate=False)
        assert False, "Failed to raise credential validation error"
    except NoCredentialsError:
        pass

def test_file_cache(session, ids):
    with tempfile.TemporaryDirectory() as d:
        file_cache = aws_assume_role_lib.JSONFileCache(d)

        dir_size = len(list(Path(d).iterdir()))
        assert dir_size == 0, "Dir is not empty"
        assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, cache=file_cache)

        assumed_role_session.client('sts').get_caller_identity()

        dir_size = len(list(Path(d).iterdir()))
        assert dir_size == 1, "Dir has wrong size({})".format(dir_size)

#TODO: these tests are brittle, need to go more specific with controlling configuration
def test_region(session, ids):
    parent_region = "us-east-1"
    session = boto3.Session(region_name=parent_region)

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn)

    assert assumed_role_session.region_name == parent_region

    assumed_role_session.client("ec2").describe_availability_zones()

    child_region = "us-east-2"
    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=child_region)

    assert assumed_role_session.region_name == child_region

    try:
        assumed_role_session.client("ec2").describe_availability_zones()
        assert False, "Failed to raise authorization error"
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != "UnauthorizedOperation":
            raise

def test_region_bool(session, ids):
    prev_region_value = os.environ.get("AWS_DEFAULT_REGION")

    region1 = "us-east-1"

    session = boto3.Session()

    os.environ["AWS_DEFAULT_REGION"] = region1

    assert session.region_name == region1

    # Test for implicit config on session that if we don't change anything, both true and false stay the same

    assumed_role_session1 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=True)
    assert assumed_role_session1.region_name == region1

    assumed_role_session2 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=False)
    assert assumed_role_session2.region_name == region1

    assumed_role_session1.client("ec2").describe_availability_zones()
    assumed_role_session2.client("ec2").describe_availability_zones()

    # Test for implicit config on session that if we create it and later change implicit config
    # true stays at the original value
    # false gets the new value

    region2 = "us-east-2"

    assumed_role_session1 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=True)
    assumed_role_session2 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=False)

    os.environ["AWS_DEFAULT_REGION"] = region2

    assert assumed_role_session1.region_name == region1, "Region mismatch: is {} should be {}".format(assumed_role_session1.region_name, region1)
    assert assumed_role_session2.region_name == region2, "Region mismatch: is {} should be {}".format(assumed_role_session2.region_name, region2)

    assumed_role_session1.client("ec2").describe_availability_zones()
    try:
        assumed_role_session2.client("ec2").describe_availability_zones()
        assert False, "Failed to raise authorization error"
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != "UnauthorizedOperation":
            raise

    # Test for explicit config contrary to implict config
    # true stays with explicit config
    # false goes to implict config

    session = boto3.Session(region_name=region1)

    assumed_role_session1 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=True)
    assumed_role_session2 = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, region_name=False)

    assert assumed_role_session1.region_name == region1
    assert assumed_role_session2.region_name == region2

    assumed_role_session1.client("ec2").describe_availability_zones()
    try:
        assumed_role_session2.client("ec2").describe_availability_zones()
        assert False, "Failed to raise authorization error"
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != "UnauthorizedOperation":
            raise

    if prev_region_value is None:
        os.environ.pop("AWS_DEFAULT_REGION")
    else:
        os.environ["AWS_DEFAULT_REGION"] = prev_region_value

def test_patch_boto3(session, ids):
    assumed_role_session = session.assume_role(RoleArn=ids.RoleArn)

    response = assumed_role_session.client("sts").get_caller_identity()
    assumed_role_arn = response["Arn"]

    assert ids.RoleArn.rsplit("/", 1)[1] == assumed_role_arn.split("/")[1]

    boto3.DEFAULT_SESSION = session

    assumed_role_session = boto3.assume_role(RoleArn=ids.RoleArn)

    response = assumed_role_session.client("sts").get_caller_identity()
    assumed_role_arn = response["Arn"]

    assert ids.RoleArn.rsplit("/", 1)[1] == assumed_role_arn.split("/")[1]

def test_lambda_session_name(session, ids):
    func_name = str(uuid.uuid4())
    identifier = str(uuid.uuid4())

    name_1 = aws_assume_role_lib.generate_lambda_session_name(
        function_name=func_name,
        identifier=identifier
    )

    assert name_1 == f"{func_name}.{identifier}"

    version = 1

    name_2 = aws_assume_role_lib.generate_lambda_session_name(
        function_name=func_name,
        function_version=version,
        identifier=identifier
    )

    assert name_2 == f"{func_name}.{version}.{identifier}"

def test_get_role_arn(session, ids):
    account_1_str = "123456789012"
    account_1_num =  123456789012

    account_2_full_str = "001234567890"
    account_2_str      =   "1234567890"
    account_2_num      =    1234567890

    role_name = str(uuid.uuid4())

    # account formatting
    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name)
    assert arn == f"arn:aws:iam::{account_1_str}:role/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_num, role_name)
    assert arn == f"arn:aws:iam::{account_1_str}:role/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_2_str, role_name)
    assert arn == f"arn:aws:iam::{account_2_full_str}:role/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_2_num, role_name)
    assert arn == f"arn:aws:iam::{account_2_full_str}:role/{role_name}"

    # partition
    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, partition="aws-cn")
    assert arn == f"arn:aws-cn:iam::{account_1_str}:role/{role_name}"

    # path
    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, path="/")
    assert arn == f"arn:aws:iam::{account_1_str}:role/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, path="te/st")
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, path="/te/st")
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, path="te/st/")
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, role_name, path="/te/st/")
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, "/" + role_name)
    assert arn == f"arn:aws:iam::{account_1_str}:role/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, "te/st/" + role_name)
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    arn = aws_assume_role_lib.get_role_arn(account_1_str, "/te/st/" + role_name)
    assert arn == f"arn:aws:iam::{account_1_str}:role/te/st/{role_name}"

    try:
        arn = aws_assume_role_lib.get_role_arn(account_1_str, "/te/st/" + role_name, path="test")
        assert False
    except Exception as e:
        pass

def test_get_assumed_role_session_arn(session, ids):
    account_1_str = "123456789012"
    account_1_num =  123456789012

    account_2_str = "1234567890"
    account_2_num =  1234567890

    role_name = str(uuid.uuid4())
    role_session_name = str(uuid.uuid4())

    # account formatting
    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_num, role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_num, role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    # partition
    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, role_name, role_session_name, partition="aws-cn")
    assert arn == f"arn:aws-cn:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    # path
    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "/" + role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "te/st/" + role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "/te/st/" + role_name, role_session_name)
    assert arn == f"arn:aws:iam::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("stack_name")
    parser.add_argument("--profile")
    parser.add_argument("test_name", nargs="*")

    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)

    ids = get_ids(session, args.stack_name)

    for name, value in globals().items():
        if name.startswith("test_") and callable(value):
            if args.test_name and name not in args.test_name:
                continue
            print("Running", name)
            value(session, ids)

if __name__ == "__main__":
    main()
