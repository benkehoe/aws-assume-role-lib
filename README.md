# aws-assume-role-lib
**Assumed role session chaining (with credential refreshing) for boto3**

The typical way to use boto3 when programmatically assuming a role is to explicitly call [`sts.AssumeRole`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.assume_role) and use the returned credentials to create a new [`boto3.Session`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html).
However, these credentials expire, and the code must explicitly handle this situation (e.g., in a Lambda function, calling `AssumeRole` in every invocation).

With `aws-assume-role-lib`, you can easily create assumed role sessions from parent sessions that automatically refresh expired credentials.

In a Lambda function that needs to assume a role, you can create the assumed role session during initialization and use it for the lifetime of the execution environment.

Note that in `~/.aws/config`, [you have the option to have profiles that assume a role based on another profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html), and this automatically handles refreshing expired credentials as well.

If you've only used `boto3.client()` and are not familiar with boto3 sessions, [here's an explainer](https://ben11kehoe.medium.com/boto3-sessions-and-why-you-should-use-them-9b094eb5ca8e).

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

# do stuff with the original credentials
print(session.client("sts").get_caller_identity()["Arn"])

# do stuff with the assumed role
print(assumed_role_session.client("sts").get_caller_identity()["Arn"])
```

In Lambda, initialize the sessions outside the handler:
```python
import os
import boto3
from aws_assume_role_lib import assume_role, generate_lambda_session_name

# Get the Lambda session
SESSION = boto3.Session()

# Get the config
ROLE_ARN = os.environ["ROLE_ARN"]
ROLE_SESSION_NAME = generate_lambda_session_name() # see below for details

# Assume the session
ASSUMED_ROLE_SESSION = assume_role(SESSION, ROLE_ARN, RoleSessionName=ROLE_SESSION_NAME)

def handler(event, context):
    # do stuff with the Lambda role using SESSION
    print(SESSION.client("sts").get_caller_identity()["Arn"])

    # do stuff with the assumed role using ASSUMED_ROLE_SESSION
    print(ASSUMED_ROLE_SESSION.client("sts").get_caller_identity()["Arn"])
```

# Interface

```
assume_role(
    # required arguments
    session:           boto3.Session,
    RoleArn:           str,

    *,
    # keyword-only arguments for AssumeRole
    RoleSessionName:   str                            = None,
    PolicyArns:        list[dict[str, str]]           = None,
    Policy:            Union[str, dict]               = None,
    DurationSeconds:   Union[int, datetime.timedelta] = None,
    Tags:              list[dict[str, str]]           = None,
    TransitiveTagKeys: list[str]                      = None,
    ExternalId:        str                            = None,
    SerialNumber:      str                            = None,
    TokenCode:         str                            = None,
    additional_kwargs: dict                           = None,

    # keyword-only arguments for returned session
    region_name:       Union[str, bool]               = None,

    # keyword-only arguments for assume_role() itself
    validate:          bool                           = True,
    cache:             dict                           = None,
)
```

`assume_role()` takes a session and a role ARN, and optionally [other keyword arguments for `sts.AssumeRole`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.assume_role).
Unlike the `AssumeRole` API call itself, `RoleArn` is required, but `RoleSessionName` is not; it's automatically generated if one is not provided.

Note that unlike the boto3 sts client method, you can provide the `Policy` parameter (the [inline session policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session)) as a `dict` rather than a serialized JSON string, and `DurationSeconds` as a `datetime.timedelta` rather than an integer.

By default, the session returned by `assume_role()` uses the same region configuration as the input session.
If you would like to set the region explicitly, pass it in the `region_name` parameter.

Note that if the parent session was created without a region passed in to the `Session` constructor, it has an implicit region, based on searching potential configuration locations.
This means that the region used by the session can change (for example, if you set `os.environ["AWS_DEFAULT_REGION"]` to a different value).
By default, if the parent session has an implicit region, the child session has an implicit region, and they would both change.
If the parent session has an implicit region, and you would like to fix the child session region to be explicitly the current value, pass `region_name=True`.
If, for some reason, you have an explicit region set on the parent, and want the child to have implicit region config, pass `region_name=False`.

By default, `assume_role()` checks if the parameters are invalid.
Without this validation, errors for these issues are more confusingly raised when the child session is first used to make an API call (boto3 doesn't make the call to retrieve credentials until they are needed).
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

# Role session names for Lambda functions
If you don't provide a role session name, the underlying `botocore` library [generates one using a timestamp](https://github.com/boto/botocore/blob/c53072ec257ef47e2fc749c384a9488fd3f3e626/botocore/credentials.py#L730).
That's the best it can do, because it doesn't have any other context.

But in a Lambda function, we do have additional context, the Lambda function itself.
If you call `generate_lambda_session_name()` inside an instance of a Lambda function, it returns a session name that corresponds to the function instance, which you can use when assuming a role in the Lambda function (either with this library's `assume_role()` or any other method).
The purpose of this is to simplify tracing usage of the session back to the function instance.

If the version is `$LATEST`, the returned value is has the format `{function_name}.{identifier}`, otherwise it has the format `{function_name}.{function_version}.{identifier}`.
The identifier is the function instance's unique ID extracted from the CloudWatch log stream name; if this fails for any reason, it's a timestamp instead.
You can override any of the values by providing them as arguments to the function.

# Caching

If you would like to cache the credentials on the file system, you can use the `JSONFileCache` class, which will create files under the directory you provide in the constructor (which it will create if it doesn't exist).
Use it like:
```python
assumed_role_session = assume_role(session, "arn:aws:iam::123456789012:role/MyRole", cache=JSONFileCache("path/to/dir"))
```
You can also use any `dict`-like object for the cache (supporting `__getitem__`/`__setitem__`/`__contains__`).
