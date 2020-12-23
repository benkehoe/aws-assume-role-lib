# aws-assume-role-lib
**Assumed role session chaining (with credential refreshing) for boto3**

The typical way to use boto3 when programmatically assuming a role is to explicitly call [`sts.AssumeRole`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.assume_role) and use the returned credentials to create a new [`boto3.Session`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html).
However, these credentials expire, and the code must explicitly handle this situation (e.g., in a Lambda function, calling `AssumeRole` in every invocation).

With `aws-assume-role-lib`, you can easily create assumed role sessions from parent sessions that automatically refresh expired credentials.

In a Lambda function that needs to assume a role, you can create the assumed role session during initialization and use it for the lifetime of the execution environment.

Note that in `~/.aws/config`, [you have the option to have profiles that assume a role based on another profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html), and this automatically handles refreshing expired credentials as well.

# Installation

```bash
pip install --user aws-assume-role-lib
```

Or just add [`aws_assume_role_lib.py`](https://raw.githubusercontent.com/benkehoe/aws-assume-role-lib/main/aws_assume_role_lib.py) to your project.

# Usage

```python
import boto3
from aws_assume_role_lib import assume_role

# Get a session
session = boto3.Session()
# or with a profile:
# session = boto3.Session(profile_name="my-profile")

# Assume the session
assumed_role_session = assume_role(session, "arn:aws:iam::123456789012:role/MyRole")

print(assumed_role_session.client("sts").get_caller_identity()["Arn"])
```

# Interface

```
assume_role(session: boto3.Session, RoleArn: str, *,
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
    additional_kwargs: typing.Dict=None)
```

`assume_role()` takes a session and a role ARN, and optionally [other keyword arguments for `sts.AssumeRole`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.assume_role).
Unlike the `AssumeRole` API call itself, `RoleArn` is required, but `RoleSessionName` is not; it's automatically generated if one is not provided.

By default, the session returned by `assume_role()` uses the same region configuration as the input session.
If you would like to set the region explicitly, pass it in the `region_name` parameter.

Note that if the parent session was created without a region passed in to the `Session` constructor, it has an implicit region, based on searching potential configuration locations.
This means that the region used by the session can change (for example, if you set `os.environ["AWS_DEFAULT_REGION"]` to a different value).
By default, if the parent session has an implicit region, the child session has an implicit region, and they would both change.
If the parent session has an implicit region, and you would like to fix the child session region to be explicitly the current value, pass `region_name=True`.
If, for some reason, you have an explicit region set on the parent, and want the child to have implicit region config, pass `region_name=False`.

By default, `assume_role()` checks if the parameters are invalid.
Without this validation, errors for these issues are more confusingly raised when the child session is first used to make an API call (boto3 does make the call to retrieve credentials until they are needed).
However, this incurs a small time penalty, so parameter validation can be disabled by passing `validate=False`.

If any new arguments are added to `AssumeRole` in the future, they can be passed in via the `additional_kwargs` argument.

The parent session is available on the child session in the `assume_role_parent_session` property.
Note this property is added by this library; ordinary boto3 sessions do not have it.

# Patching boto3

You can make the `assume_role()` function available directly in boto3 by calling `patch_boto3()`.
This creates a `boto3.assume_role(RoleArn, ...)` function (note that it does not take a session, it uses the same default session as `boto3.client()`), and adds a `boto3.Session.assume_role()` method.
So usage for that looks like:

```python
import boto3
import aws_assume_role_lib
aws_assume_role_lib.patch_boto3()

# basically equivalent to:
# assume_role(boto3.Session(), "arn:aws:iam::123456789012:role/MyRole")
assumed_role_session = boto3.assume_role("arn:aws:iam::123456789012:role/MyRole")

session = boto3.Session(profile_name="my-profile")
assumed_role_session = session.assume_role("arn:aws:iam::123456789012:role/MyRole")
```

# Caching

If you would like to cache the credentials on the file system, you can use the `JSONFileCache` class, which will create files under the directory you provide in the constructor (which it will create if it doesn't exist).
Use it like:
```python
assumed_role_session = assume_role(session, "arn:aws:iam::123456789012:role/MyRole", cache=JSONFileCache("path/to/dir"))
```
You can also use any `dict`-like object for the cache (supporting `__getitem__`/`__setitem__`/`__contains__`).
