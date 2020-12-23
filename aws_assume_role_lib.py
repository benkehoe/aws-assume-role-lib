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

import boto3
import botocore

__version__ = "1.2.0"

__all__ = ["assume_role", "JSONFileCache"]

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
            "TokenCode"]:
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
            region_name=region_name,
            validate=validate,
            cache=cache,
            additional_kwargs=additional_kwargs
        )
    wrapper.__name__ = assume_role.__name__
    setattr(boto3, assume_role.__name__, wrapper)

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
