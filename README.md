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

`assume_role()` takes a session and a role ARN, and optionally [other keyword arguments for `sts.AssumeRole`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html#STS.Client.assume_role).
Unlike the `AssumeRole` API call itself, `RoleArn` is required, but `RoleSessionName` is not; it's automatically generated if one is not provided.
If any new arguments are added to `AssumeRole` in the future, they can be passed in via the `additional_kwargs` argument.

By default, `assume_role()` checks if the parent session does not have credentials or if the parameters are invalid.
Without this validation, errors for these issues are more confusingly raised when the child session is first used to make an API call (boto3 does not try to retrieve credentials until they are needed).
However, this incurs a small time penalty, so it can be disabled by passing `validate=False`.

The parent session is available on the child session in the `assume_role_parent_session` property.
Note this property is added by this library; ordinary boto3 sessions do not have it.
