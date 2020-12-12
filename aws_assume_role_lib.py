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

import boto3
import botocore

__version__ = "1.0.0"

__all__ = ["assume_role"]

def assume_role(session: boto3.Session, RoleArn: str, *,
        RoleSessionName: str=None,
        PolicyArns: typing.List[typing.Dict[str, str]]=None,
        Policy: typing.Union[str, typing.Dict]=None,
        DurationSeconds: int=None,
        Tags: typing.List[typing.Dict[str, str]]=None,
        TransitiveTagKeys:typing.List[str]=None,
        ExternalId: str=None,
        SerialNumber: str=None,
        TokenCode: str=None,
        validate: bool=True,
        additional_kwargs: typing.Dict=None) -> boto3.Session:
    """Produce a boto3 Session using the given role, assuming it from the input session

    Unlike creating a session with the credentials returned directly
    by sts.AssumeRole, the returned session will refresh the credentials
    automatically when they expire by calling AssumeRole again.

    By default, the parameters and session credentials are checked so that errors
    can be raised at this point, rather than more confusingly when the first call
    is made using the child session. This can be disabled by setting validate=False.

    The parent session is available on the child session
    in the property assume_role_parent_session.

    Additional arguments for AssumeRole, if any are added in the future,
    can be passed in additional_kwargs."""

    botocore_session = session._session

    if Policy is not None and not isinstance(Policy, str):
        Policy = json.dumps(Policy)

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

    if validate:
        validate_args = extra_args.copy()
        validate_args["RoleArn"] = RoleArn
        if "RoleSessionName" not in validate_args:
            # this gets generated later if it's not present
            validate_args["RoleSessionName"] = "ToBeGenerated"
        shape = session.client("sts")._service_model.shape_for("AssumeRoleRequest")
        botocore.validate.validate_parameters(validate_args, shape)

        credentials = botocore_session.get_credentials()
        if not credentials:
            raise botocore.exceptions.NoCredentialsError

    assume_role_provider = AssumeRoleProvider(
        botocore_session.create_client,
        botocore_session.get_credentials(),
        RoleArn,
        extra_args=extra_args,
    )

    assumed_role_botocore_session = botocore.session.Session()
    assumed_role_botocore_session.register_component(
        "credential_provider",
        botocore.credentials.CredentialResolver([assume_role_provider])
    )

    assumed_role_boto3_session = boto3.Session(botocore_session=assumed_role_botocore_session)

    assumed_role_boto3_session.assume_role_parent_session = session

    return assumed_role_boto3_session

class AssumeRoleProvider(botocore.credentials.CredentialProvider):
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
