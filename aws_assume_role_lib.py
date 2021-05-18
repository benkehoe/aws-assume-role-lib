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

__version__ = "1.7.0" # update here and pyproject.toml

__all__ = ["assume_role", "get_role_arn", "get_assumed_role_arn", "generate_lambda_session_name", "patch_boto3", "JSONFileCache"]

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

    return f"arn:{partition}:iam::{account_id}:assumed-role/{role_name}/{role_session_name}"

def assume_role(session: boto3.Session, RoleArn: str, *,
        RoleSessionName: str=None,
        PolicyArns: typing.List[typing.Dict[str, str]]=None,
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
        region_name = botocore_session.instance_variables().get('region')

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
            PolicyArns: typing.List[typing.Dict[str, str]]=None,
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
