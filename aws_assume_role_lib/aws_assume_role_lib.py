# Copyright 2020 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Assumed role session chaining (with credential refreshing) for boto3.

This library provides the ability to create boto3 Sessions that use a given
role, assuming that role from a parent session, in a way such that the child
session can refresh its credentials when they expire by implicitly calling
AssumeRole again."""

import typing
import json
import datetime
import os
import re
import numbers
import string
import random

import boto3
import botocore
import botocore.configprovider
import botocore.credentials
import botocore.exceptions
import botocore.session
import botocore.validate

__version__ = "2.10.0" # update here and pyproject.toml

__all__ = [
    "assume_role",
    "get_role_arn",
    "get_assumed_role_session_arn",
    "generate_lambda_session_name",
    "patch_boto3",
    "JSONFileCache",
    "AUTOMATIC_ROLE_SESSION_NAME",
]

class _ParentSessionProvider(botocore.configprovider.BaseProvider):
    def __init__(self, name: str, parent_session: botocore.session.Session):
        self.parent_session = parent_session
        self.name = name

    def provide(self):
        return self.parent_session.get_config_variable(self.name)

def _set_parent_session_provider(parent_session: botocore.session.Session, child_session: botocore.session.Session, name: str):
    # first check if an explicit value has been set in the child
    # otherwise get the value from the parent
    chain_provider = botocore.configprovider.ChainProvider([
        botocore.configprovider.InstanceVarProvider(name, child_session),
        _ParentSessionProvider(name, parent_session)
    ])
    config_store = child_session.get_component("config_store")
    config_store.set_config_provider(name, chain_provider)

# Force people to specify the path, which has a default in botocore
class JSONFileCache(botocore.credentials.JSONFileCache):
    """JSON file cache.

    This provides a dict like interface that stores JSON serializable
    objects.
    The objects are serialized to JSON and stored in a file.  These
    values can be retrieved at a later time.
    """

    def __init__(self, dir_path):
        super().__init__(working_dir=dir_path)

def get_role_arn(
        account_id: typing.Union[str, int],
        role_name: str,
        path: str="",
        partition: str="aws"):
    """Get a correctly-formatted IAM role ARN.

    You can provide the path separately or as part of the role name."""
    if isinstance(account_id, numbers.Number):
        account_id = str(int(account_id))
    if isinstance(account_id, str) and len(account_id) < 12:
        account_id = account_id.rjust(12, "0")

    if "/" in role_name and path:
        raise ValueError("Path cannot be given in both role_name and path")

    if "/" in role_name:
        path, role_name = role_name.rsplit("/", 1)

    if path == "/":
        path = ""
    if path.startswith("/"):
        path = path[1:]
    if path and not path.endswith("/"):
        path = path + "/"

    return f"arn:{partition}:iam::{account_id}:role/{path}{role_name}"

def get_assumed_role_session_arn(
        account_id: typing.Union[str, int],
        role_name: str,
        role_session_name: str,
        partition: str="aws"):
    """Get a correctly-formatted IAM assumed role session ARN.

    Note these ARNs do not contain the role's path, if it has one.
    If you provide the role name with path, it will be stripped off."""
    if isinstance(account_id, numbers.Number):
        account_id = str(int(account_id))
    if isinstance(account_id, str) and len(account_id) < 12:
        account_id = account_id.rjust(12, "0")

    if "/" in role_name:
        role_name = role_name.rsplit("/", 1)[1]

    return f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/{role_session_name}"

AUTOMATIC_ROLE_SESSION_NAME = "AUTOMATIC_ROLE_SESSION_NAME_!#$%^&*()" # use invalid chars

def assume_role(session: boto3.Session, RoleArn: str, *,
        RoleSessionName: str=None,
        PolicyArns: typing.Union[typing.List[typing.Dict[str, str]], typing.List[str]]=None,
        Policy: typing.Union[str, typing.Dict]=None,
        DurationSeconds: typing.Union[int, datetime.timedelta]=None,
        Tags: typing.List[typing.Dict[str, str]]=None,
        TransitiveTagKeys:typing.List[str]=None,
        ExternalId: str=None,
        SerialNumber: str=None,
        TokenCode: str=None,
        SourceIdentity: str=None,
        region_name: typing.Union[str, bool]=None,
        validate: bool=True,
        cache: dict=None,
        additional_kwargs: typing.Dict=None) -> boto3.Session:
    """Produce a boto3 Session using the given role, assumed using the input session.

    Unlike creating a session with the credentials returned directly
    by sts.AssumeRole, the returned session will refresh the credentials
    automatically when they expire by calling AssumeRole again.

    By default, the parameters are checked so that errors can be raised
    at this point, rather than more confusingly when the first call
    is made using the child session.
    This can be disabled by setting validate=False.

    The parent session is available on the child session
    in the property assume_role_parent_session.

    Additional arguments for AssumeRole, if any are added in the future,
    can be passed in additional_kwargs."""

    botocore_session = session._session

    if not RoleSessionName and SourceIdentity:
        RoleSessionName = SourceIdentity
    elif RoleSessionName == AUTOMATIC_ROLE_SESSION_NAME:
        RoleSessionName = None

    if PolicyArns:
        PolicyArns = [{"arn": value} if isinstance(value, str) else value for value in PolicyArns]

    if Policy is not None and not isinstance(Policy, str):
        Policy = json.dumps(Policy)

    if isinstance(DurationSeconds, datetime.timedelta):
        DurationSeconds = int(DurationSeconds.total_seconds())

    extra_args = {}
    if additional_kwargs:
        extra_args.update(additional_kwargs)

    for var_name in [
            "RoleSessionName",
            "PolicyArns",
            "Policy",
            "DurationSeconds",
            "Tags",
            "TransitiveTagKeys",
            "ExternalId",
            "SerialNumber",
            "TokenCode",
            "SourceIdentity"]:
        value = locals()[var_name]
        if value is not None:
            extra_args[var_name] = value

    credentials = botocore_session.get_credentials()
    if not credentials:
        raise botocore.exceptions.NoCredentialsError

    if validate:
        validate_args = extra_args.copy()
        validate_args["RoleArn"] = RoleArn
        if "RoleSessionName" not in validate_args:
            # this gets generated later if it's not present
            validate_args["RoleSessionName"] = "ToBeGenerated"
        shape = session.client("sts")._service_model.shape_for("AssumeRoleRequest")
        botocore.validate.validate_parameters(validate_args, shape)

    assume_role_provider = ProgrammaticAssumeRoleProvider(
        botocore_session.create_client,
        credentials,
        RoleArn,
        extra_args=extra_args,
        cache=cache,
    )

    assumed_role_botocore_session = botocore.session.Session()
    assumed_role_botocore_session.register_component(
        "credential_provider",
        botocore.credentials.CredentialResolver([assume_role_provider])
    )

    if region_name is True:
        region_name = session.region_name
    elif region_name is False:
        region_name = None
    elif region_name is None:
        try:
            _set_parent_session_provider(
                botocore_session,
                assumed_role_botocore_session,
                "region")
        except Exception as e:
            raise RuntimeError(
                "Unexpected breakage of botocore config API. " +
                "Fall back to setting region_name=True to use parent session region " +
                "or region=False to use implicit region.") from e

    session_kwargs = {
        "botocore_session": assumed_role_botocore_session,
        "region_name": region_name,
    }

    assumed_role_boto3_session = boto3.Session(**session_kwargs)

    assumed_role_boto3_session.assume_role_parent_session = session

    return assumed_role_boto3_session

def patch_boto3():
    """Add boto3.assume_role() and boto3.Session.assume_role().

    Each has the same interface as assume_role() except they do not take
    a session object as input."""
    setattr(boto3.Session, assume_role.__name__, assume_role)

    def wrapper(RoleArn: str, *,
            RoleSessionName: str=None,
            PolicyArns: typing.Union[typing.List[typing.Dict[str, str]], typing.List[str]]=None,
            Policy: typing.Union[str, typing.Dict]=None,
            DurationSeconds: typing.Union[int, datetime.timedelta]=None,
            Tags: typing.List[typing.Dict[str, str]]=None,
            TransitiveTagKeys:typing.List[str]=None,
            ExternalId: str=None,
            SerialNumber: str=None,
            TokenCode: str=None,
            SourceIdentity: str=None,
            region_name: typing.Union[str, bool]=None,
            validate: bool=True,
            cache: dict=None,
            additional_kwargs: typing.Dict=None) -> boto3.Session:
        """Produce a boto3 Session using the given role.

        Unlike creating a session with the credentials returned directly
        by sts.AssumeRole, the returned session will refresh the credentials
        automatically when they expire by calling AssumeRole again.

        By default, the parameters are checked so that errors can be raised
        at this point, rather than more confusingly when the first call
        is made using the child session.
        This can be disabled by setting validate=False.

        The parent session is available on the child session
        in the property assume_role_parent_session.

        Additional arguments for AssumeRole, if any are added in the future,
        can be passed in additional_kwargs."""
        session = boto3._get_default_session()
        return assume_role(session, RoleArn,
            RoleSessionName=RoleSessionName,
            PolicyArns=PolicyArns,
            Policy=Policy,
            DurationSeconds=DurationSeconds,
            Tags=Tags,
            TransitiveTagKeys=TransitiveTagKeys,
            ExternalId=ExternalId,
            SerialNumber=SerialNumber,
            TokenCode=TokenCode,
            SourceIdentity=SourceIdentity,
            region_name=region_name,
            validate=validate,
            cache=cache,
            additional_kwargs=additional_kwargs
        )
    wrapper.__name__ = assume_role.__name__
    setattr(boto3, assume_role.__name__, wrapper)

def generate_lambda_session_name(
        function_name: str=None,
        function_version: str=None,
        identifier: str=None):
    """For Lambda functions, generate a role session name that identifies the function.

    The returned value is in one of the following forms:
    {function_name}
    {function_name}.{identifier}
    {function_name}.{function_version}.{identifier}

    The function name must be retrievable from the AWS_LAMBDA_FUNCTION_NAME
    environment variable, or it must be provided.

    The function version is looked for in the AWS_LAMBDA_FUNCTION_VERSION
    environment variable by default. Function versions of $LATEST
    are treated the same as missing function versions.

    The identifier is taken from the log stream name in the
    AWS_LAMBDA_LOG_STREAM_NAME environment variable by default; if it is not
    provided and this cannot be found, it's a timestamp if the identifier can be
    at least 14 characters long (to provide for second-level precision),
    otherwise it is a random string.

    The maximum role session name length is 64 characters. To ensure this, and
    to provide at least 4 characters of the identifier when it is used, the
    following rules apply, in order:
    1. If the function name is longer than 59 characters, the session name is the
        truncated function name.
    2. If the function name plus the function version is longer than 59 characters,
        the session name is the function name plus the identifier, truncated.
    3. Otherwise, the session name is the function name plus the version (if one
        is found and not $LATEST) plus the identifier, truncated.
    """
    if not function_name:
        function_name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

    name_component = function_name

    if not function_version:
        function_version = os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "")

    if function_version and function_version != "$LATEST":
        version_component = "." + str(function_version)
    else:
        version_component = ""

    def _get_identifier(max_length):
        if identifier:
            return identifier
        # the execution environment has a unique ID, but it's not exposed directly
        # the log stream name (currently) includes it and looks like
        # 2020/01/31/[$LATEST]3893xmpl7fac4485b47bb75b671a283c
        log_stream_name = os.environ.get("AWS_LAMBDA_LOG_STREAM_NAME", "")
        match = re.search(r"\w+$", log_stream_name)
        if match:
            return match.group()[:max_length]
        elif max_length >= 14:
            # enough for second-level precision
            return datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S%f")[:max_length]
        else:
            chars = string.ascii_lowercase + string.digits
            return ''.join(random.choice(chars) for _ in range(max_length))

    # truncate for max role session name length of 64
    if len(name_component) > 59:
        # don't bother with the identifier unless we can get
        # at least four characters of it
        value = name_component[:64]
    elif len(name_component) + len(version_component) > 59:
        # don't bother with the version if we can't get it
        max_length = 63 - len(name_component)
        identifier_component = "." + _get_identifier(max_length)
        value = f"{name_component}{identifier_component}"[:64]
    else:
        max_length = 63 - (len(name_component) + len(version_component))
        identifier_component = "." + _get_identifier(max_length)
        value = f"{name_component}{version_component}{identifier_component}"[:64]

    clean_value = re.sub(r"[^a-zA-Z0-9_=,.@-]+", "_", value)

    return clean_value

class ProgrammaticAssumeRoleProvider(botocore.credentials.CredentialProvider):
    METHOD = "assume-role"

    def __init__(self, client_creator, credential_loader, role_arn,
            extra_args=None, cache=None):
        self._client_creator = client_creator
        self._credential_loader = credential_loader
        self._role_arn = role_arn
        self._extra_args = extra_args
        self._fetcher = None
        if cache is None:
            cache = {}
        self._cache = cache

    def _get_fetcher(self):
        if not self._fetcher:
            self._fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
                self._client_creator,
                self._credential_loader,
                self._role_arn,
                extra_args=self._extra_args,
                cache=self._cache
            )
        return self._fetcher

    def load(self):
        return botocore.credentials.DeferredRefreshableCredentials(
            self._get_fetcher().fetch_credentials,
            self.METHOD
        )

def main(arg_strs=None, exit=None):
    import argparse
    import sys
    import textwrap
    from datetime import datetime

    if not exit:
        exit = sys.exit

    TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

    def _json_dict_loader(input):
        try:
            data = json.loads(input)
            if not isinstance(data, dict):
                raise argparse.ArgumentTypeError("JSON value must be an object")
            return data
        except json.decoder.JSONDecodeError:
            raise argparse.ArgumentTypeError("must be a valid JSON object")

    def _dict_loader(input):
        try:
            data = json.loads(input)
            if not isinstance(data, dict):
                raise argparse.ArgumentTypeError("JSON value must be an object")
            return data
        except json.decoder.JSONDecodeError:
            pass
        return dict(v.split('=', 1) for v in input.split(','))

    def _list_loader(input):
        try:
            data = json.loads(input)
            if not isinstance(data, list):
                raise argparse.ArgumentTypeError("JSON value must be a list")
            return data
        except json.decoder.JSONDecodeError:
            pass
        return input.split(',')

    def _policy_arns_loader(input):
        try:
            data = json.loads(input)
            if not isinstance(data, (dict, list)):
                raise argparse.ArgumentTypeError("JSON value must be a list or object")
            return data
        except json.decoder.JSONDecodeError:
            pass
        return input.split(',')

    parser = argparse.ArgumentParser(
        prog="python -m aws_assume_role_lib",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
    Assume the given role and print out the resulting credentials.

    For env var usage, export the output:
    export $( <invocation here> )

    In general, it's better to make profiles in ~/.aws/config for role assumption,
    which makes use of the AWS SDK's built-in support for role assumption.
    It also gets you automatic credential refreshing from the SDKs,
    unlike exporting them through this method.

    Example config profile for role assumption:

    [profile my-assumed-role]
    role_arn = arn:aws:iam::123456789012:role/MyRole
    # optional: role_session_name = MyRoleSessionName
    source_profile = profile-to-call-assume-role-with
    # or:
    # credential_source = Environment
    # credential_source = Ec2InstanceMetadata
    # credential_source = EcsContainer"""))

    parser.add_argument("--profile", help="the AWS config profile to use")
    parser.add_argument("RoleArn")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--env", action="store_const", const="env", dest="format", help="print as env vars (default)")
    group.add_argument("--json", action="store_const", const="json", dest="format", help="print credential_process-formatted JSON to stdout")
    parser.set_defaults(format="env")

    parser.add_argument("--RoleSessionName", metavar="ROLE_SESSION_NAME")
    parser.add_argument("--PolicyArns", type=_policy_arns_loader, metavar="POLICY_ARNS", help="Arn1,Arn2 JSON list or JSON object")
    parser.add_argument("--Policy", type=_json_dict_loader, help="JSON object")
    parser.add_argument("--DurationSeconds", type=int, metavar="DURATION_SECONDS")
    parser.add_argument("--Tags", type=_dict_loader, help="Key1=Value1,Key2=Value2 or JSON object")
    parser.add_argument("--TransitiveTagKeys", type=_list_loader, metavar="TRANSITIVE_TAG_KEYS", help="Key1,Key2 or JSON list")
    parser.add_argument("--ExternalId", metavar="EXTERNAL_ID")
    parser.add_argument("--SerialNumber", metavar="SERIAL_NUMBER")
    parser.add_argument("--TokenCode", metavar="TOKEN_CODE")
    parser.add_argument("--SourceIdentity", metavar="SOURCE_IDENTITY")
    parser.add_argument("--additional-kwargs", type=_json_dict_loader, help="JSON object")

    args = parser.parse_args(args=arg_strs)

    try:
        session = boto3.Session(profile_name=args.profile)
    except Exception as error:
        print("Unable to locate credentials: {}".format(error), file=sys.stderr)
        exit(3); return
    if not session.get_credentials():
        print("Unable to locate credentials", file=sys.stderr)
        exit(3); return

    assume_role_args = vars(args).copy()
    for field in ["profile", "format"]:
        assume_role_args.pop(field)
    assume_role_args.update({
        "session": session,
        "region_name": True, # doesn't really matter
    })

    try:
        assumed_role_session = assume_role(**assume_role_args)
        credentials = assumed_role_session.get_credentials()
        frozen_credentials = credentials.get_frozen_credentials()
    except botocore.exceptions.ClientError as error:
        code = error.response["Error"]["Code"]
        msg = error.response["Error"]["Message"]
        print("Error when assuming role [{}]: {}".format(code, msg), file=sys.stderr)
        exit(4); return
    except Exception as error:
        print("Error when assuming role: {}".format(error), file=sys.stderr)
        exit(4); return

    expiration = None
    if hasattr(credentials, '_expiry_time') and credentials._expiry_time:
        if isinstance(credentials._expiry_time, datetime):
            expiration = credentials._expiry_time.strftime(TIME_FORMAT)
        elif isinstance(credentials._expiry_time, str):
            expiration = credentials._expiry_time

    if args.format == "json":
        data = {
            "Version": 1,
            "AccessKeyId": frozen_credentials.access_key,
            "SecretAccessKey": frozen_credentials.secret_key,
            "SessionToken": frozen_credentials.token,
        }
        if expiration:
            data["Expiration"] = expiration

        print(json.dumps(data, indent=2))
    elif args.format == "env":
        lines = [
            "AWS_ACCESS_KEY_ID={}".format(frozen_credentials.access_key),
            "AWS_SECRET_ACCESS_KEY={}".format(frozen_credentials.secret_key),
            "AWS_SESSION_TOKEN={}".format(frozen_credentials.token),
        ]
        if expiration:
            lines.append("AWS_CREDENTIALS_EXPIRATION={}".format(expiration))
        print("\n".join(lines))
    else:
        print("Unexpected format {}".format(args.format), file=sys.stderr)
        exit(-1); return

if __name__ == "__main__":
    main()
