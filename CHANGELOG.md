# Changelog

`aws-assume-role-lib` uses [monotonic versioning](http://blog.appliedcompscilab.com/monotonic_versioning_manifesto/).

## v2.10
* Fix CLI support
* Update boto3 version requirement for `SourceIdentity` validation

## v2.9
* Fixed `get_assumed_role_session_arn()`, which incorrectly used `iam` instead of `sts` in the ARN.
* If `RoleSessionName` is not provided but `SourceIdentity` is, the `SourceIdentity` value will be used for `RoleSessionName`, rather than the `botocore`-generated value.
    * Added special value `AUTOMATIC_ROLE_SESSION_NAME`; setting `RoleSessionName` to this will cause it to use pre-2.8 behavior (i.e., always use `botocore`-generated value).
* Updated for [PEP 561](https://www.python.org/dev/peps/pep-0561/) (typing) compliance. Link to single-file module has changed to https://raw.githubusercontent.com/benkehoe/aws-assume-role-lib/stable/aws_assume_role_lib/aws_assume_role_lib.py
    * Link to single-file module now uses `stable` branch, which will point to a release commit.

## v2.8
* If `region_name=None` (the default), the child session region is linked to the parent session region (not copied, which happens if `region_name=True`). If the parent session is using a config profile, this means the child session will have a region, rather than needing/using a separately-set region (e.g., via the `AWS_DEFAULT_REGION` environment variable). For safety, this release increments the [compatibility version](http://blog.appliedcompscilab.com/monotonic_versioning_manifesto/) to 2.
* Added [command line functionality](README.md#command-line-use).
* `PolicyArns` can be provided as a list of ARNs in addition to the verbose list-of-single-element-dicts required by the API.

## v1.7
* `generate_lambda_session_name()` now performs truncation to return a value that is always 64 characters or less.

## v1.6
* Ensured new functions get imported when doing `from aws_assume_role_lib import *`.

## v1.5
* Added `get_role_arn()` and `get_assumed_role_session_arn()` functions.

## v1.4
* Added support for the new [`SourceIdentity`](https://aws.amazon.com/blogs/security/how-to-relate-iam-role-activity-to-corporate-identity/) parameter.

Note that you don't need to wait for any future new parameters to be added to the library to start using them, because they can be passed in through the `additional_kwargs` parameter.
For `SourceIdentity`, before v1.4 this would have looked like including the parameter `additional_kwargs={'SourceIdentity': '...'}` to the `assume_role()` call.

## v1.3
* Added the `generate_lambda_session_name()` function.

## v1.2
* Added `region_name` parameter.
* Added `patch_boto3()` function.
