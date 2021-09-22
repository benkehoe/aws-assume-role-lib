import argparse
import uuid
import json
import tempfile
import os
import datetime
from pathlib import Path
from collections import namedtuple
import sys
import contextlib
import io

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

def test_policy_arns(session, ids):
    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, PolicyArns=[
        "arn:aws:iam::aws:policy/AWSDenyAll"
    ])

    response = assumed_role_session.client('sts').get_caller_identity()

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, PolicyArns=[
        {"arn": "arn:aws:iam::aws:policy/AWSDenyAll"}
    ])

    response = assumed_role_session.client('sts').get_caller_identity()

    try:
        assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn, PolicyArns="arn:aws:iam::aws:policy/AWSDenyAll")
        assert False
    except botocore.exceptions.ParamValidationError:
        pass

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
    session = boto3.Session(region_name=parent_region, botocore_session=session._session)

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

    session = boto3.Session(botocore_session=session._session)

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

    session = boto3.Session(region_name=region1, botocore_session=session._session)

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

def test_region_config_provider(session, ids):
    old_botocore_session = botocore.session.Session()
    new_botocore_session = botocore.session.Session()

    aws_assume_role_lib._set_parent_session_provider(
                old_botocore_session,
                new_botocore_session,
                "region")

    # initial values can be anything, must be the same
    assert new_botocore_session.get_config_variable("region") == old_botocore_session.get_config_variable("region")

    prev_region_value = os.environ.get("AWS_DEFAULT_REGION")

    # set the env var, both should get it
    region_1 = str(uuid.uuid4())
    os.environ["AWS_DEFAULT_REGION"] = region_1

    assert old_botocore_session.get_config_variable("region") == region_1
    assert new_botocore_session.get_config_variable("region") == region_1

    os.environ.pop("AWS_DEFAULT_REGION")

    # set the instance var on old, both should get it
    region_2 = str(uuid.uuid4())
    old_botocore_session.set_config_variable("region", region_2)

    assert old_botocore_session.get_config_variable("region") == region_2
    assert new_botocore_session.get_config_variable("region") == region_2

    # set the env var again, neither should get it
    region_3 = str(uuid.uuid4())
    os.environ["AWS_DEFAULT_REGION"] = region_3

    assert old_botocore_session.get_config_variable("region") == region_2
    assert new_botocore_session.get_config_variable("region") == region_2

    if prev_region_value is None:
        os.environ.pop("AWS_DEFAULT_REGION")
    else:
        os.environ["AWS_DEFAULT_REGION"] = prev_region_value

    # set the instance var on new, only new should get it
    region_4 = str(uuid.uuid4())
    new_botocore_session.set_config_variable("region", region_4)
    assert old_botocore_session.get_config_variable("region") != region_4
    assert new_botocore_session.get_config_variable("region") == region_4

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
    func_name = uuid.uuid4().hex[:16]
    identifier = uuid.uuid4().hex[:16]

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

def test_lambda_session_name_truncation(session, ids):
    s = "123456789a123456789b123456789c123456789d123456789e123456789f123456789g123456789"

    def test(n, v, i, val):
        value = aws_assume_role_lib.generate_lambda_session_name(
            function_name=n,
            function_version=v,
            identifier=i
        )

        assert value == val, (value, val)

    test(
        s[:65],
        1,
        s[:5],
        "123456789a123456789b123456789c123456789d123456789e123456789f1234"
    )

    test(
        s[:62],
        5,
        s,
        "123456789a123456789b123456789c123456789d123456789e123456789f12"
    )

    test(
        s[:62],
        None,
        s,
        "123456789a123456789b123456789c123456789d123456789e123456789f12"
    )

    test(
        s[:59],
        5,
        s,
        f"123456789a123456789b123456789c123456789d123456789e123456789.{s[:4]}"
    )

    test(
        s[:59],
        None,
        s,
        f"123456789a123456789b123456789c123456789d123456789e123456789.{s[:4]}"
    )

    test(
        s[:50],
        3,
        s[:2],
        f"123456789a123456789b123456789c123456789d123456789e.3.{s[:2]}"
    )

    value = aws_assume_role_lib.generate_lambda_session_name(
        function_name=s[:32],
        function_version=2,
        identifier=uuid.uuid4().hex
    )

    assert len(value) == 64

    value = aws_assume_role_lib.generate_lambda_session_name(
        function_name=s[:57],
        function_version=2,
        identifier=None
    )

    assert len(value) == 64

    value = aws_assume_role_lib.generate_lambda_session_name(
        function_name=s[:37],
        function_version=2,
        identifier=None
    )

    # 37 + 2 + 21 (timestamp)
    assert len(value) == 60

def test_set_session_name_from_source_identity(session, ids):
    session_name = str(uuid.uuid4())
    source_identity = str(uuid.uuid4())

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn,
        RoleSessionName=session_name,
        SourceIdentity=source_identity)

    response = assumed_role_session.client('sts').get_caller_identity()
    assert response["Arn"].split("/")[-1] == session_name

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn,
        SourceIdentity=source_identity)

    response = assumed_role_session.client('sts').get_caller_identity()
    assert response["Arn"].split("/")[-1] == source_identity

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn,
        RoleSessionName=aws_assume_role_lib.AUTOMATIC_ROLE_SESSION_NAME,
        SourceIdentity=source_identity)

    response = assumed_role_session.client('sts').get_caller_identity()
    assert response["Arn"].split("/")[-1] != aws_assume_role_lib.AUTOMATIC_ROLE_SESSION_NAME
    assert response["Arn"].split("/")[-1] != source_identity

    assumed_role_session = aws_assume_role_lib.assume_role(session, RoleArn=ids.RoleArn,
        RoleSessionName=aws_assume_role_lib.AUTOMATIC_ROLE_SESSION_NAME)

    response = assumed_role_session.client('sts').get_caller_identity()
    assert response["Arn"].split("/")[-1] != aws_assume_role_lib.AUTOMATIC_ROLE_SESSION_NAME

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
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_num, role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_num, role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    # partition
    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, role_name, role_session_name, partition="aws-cn")
    assert arn == f"arn:aws-cn:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    # path
    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "/" + role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "te/st/" + role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

    arn = aws_assume_role_lib.get_assumed_role_session_arn(
        account_1_str, "/te/st/" + role_name, role_session_name)
    assert arn == f"arn:aws:sts::{account_1_str}:assumed-role/{role_name}/{role_session_name}"

@contextlib.contextmanager
def redirect_stdout_stderr(out, err):
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = out
    sys.stderr = err
    try:
        yield
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

def test_cli(session, ids):
    args = []
    if session.profile_name:
        args.extend(["--profile", session.profile_name])

    args.append(ids.RoleArn)

    session_name = str(uuid.uuid4())
    args.extend(["--RoleSessionName", session_name])

    def run_test(*new_args):
        the_args = args.copy()
        the_args.extend(new_args)
        stdout = io.StringIO()
        stderr = io.StringIO()
        code_holder = []
        def exit(code):
            code_holder.append(code)
        with redirect_stdout_stderr(stdout, stderr):
            aws_assume_role_lib.main(the_args, exit=exit)
        if code_holder:
            code = code_holder[0]
        else:
            code = 0
        return code, stdout.getvalue(), stderr.getvalue()

    code, out, err = run_test()
    assert code == 0
    assert len(err) == 0
    out_data = [line.split("=", 1)[0] for line in out.splitlines()]
    assert len(out_data) == 4
    for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CREDENTIALS_EXPIRATION"]:
        assert key in out_data

    code, out, err = run_test("--json")
    assert code == 0
    assert len(err) == 0
    out_data = json.loads(out)
    assert len(out_data) == 5
    assert out_data["Version"] == 1
    for key in ["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"]:
        assert key in out_data

    code, out, err = run_test("--env")
    assert code == 0
    assert len(err) == 0
    out_data = [line.split("=", 1)[0] for line in out.splitlines()]
    assert len(out_data) == 4
    for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CREDENTIALS_EXPIRATION"]:
        assert key in out_data

    code, out, err = run_test("--PolicyArns", "arn:aws:iam::aws:policy/AWSDenyAll,arn:aws:iam::aws:policy/AdministratorAccess")
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test("--PolicyArns", json.dumps(["arn:aws:iam::aws:policy/AWSDenyAll", "arn:aws:iam::aws:policy/AdministratorAccess"]))
    assert code == 0
    assert len(err) == 0

    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "sns:*",
            "Resource": "*"
        }]
    }
    code, out, err = run_test("--Policy", json.dumps(policy))
    assert code == 0
    assert len(err) == 0

    # double encode
    code, out, err = run_test("--Policy", json.dumps(json.dumps(policy)))
    assert code == 2
    assert len(err) != 0

    code, out, err = run_test("--DurationSeconds", "3600")
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test("--DurationSeconds", "xxx")
    assert code == 4
    assert len(out) == 0
    assert len(err) != 0

    code, out, err = run_test("--Tags", "foo=bar,spam=eggs")
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test("--Tags", json.dumps({"foo": "bar", "spam": "eggs"}))
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test("--Tags", json.dumps(["foo", "bar"]))
    assert code == 2
    assert len(err) != 0

    code, out, err = run_test(
        "--Tags",
        json.dumps({"foo": "bar", "spam": "eggs"}),
        "--TransitiveTagKeys",
        "foo"
    )
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test(
        "--Tags",
        json.dumps({"foo": "bar", "spam": "eggs"}),
        "--TransitiveTagKeys",
        json.dumps(["foo"])
    )
    assert code == 0
    assert len(err) == 0

    code, out, err = run_test(
        "--Tags",
        json.dumps({"foo": "bar", "spam": "eggs"}),
        "--TransitiveTagKeys",
        json.dumps({"foo": "bar"})
    )
    assert code == 2
    assert len(err) != 0

    code, out, err = run_test("--additional-kwargs", json.dumps({"foo": "bar"}))
    assert code == 4
    assert len(out) == 0
    assert len(err) != 0

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--profile")
    parser.add_argument("stack_name")
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
