# Changelog

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
