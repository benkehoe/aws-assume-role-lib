# Lambda demo

The code in this directory demonstrates the benefit `aws-assume-role-lib` provides when assuming roles in Lambda functions.
It also demonstrates the use of the [SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html) parameter, and the [`aws-error-utils`](https://github.com/benkehoe/aws-error-utils) library.

The functionality of the four Lambda functions is identical; the purpose is to show the simplification from the basic approach of making an `AssumeRole` call in every invocation.

## Setup

1. Install the [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html).
2. Run `deploy.py`

This creates two stacks, by default named `aws-assume-role-lib-demo-stack1` and `aws-assume-role-lib-demo-stack2`.
By default, they'll be created in the same account using whatever credentials you've set.
You can put them in separate accounts by using separate profiles with `--stack1-profile` and `--stack2-profile`.

`stack1` contains a role to assume, an S3 bucket (that the role does not have access to), and a DynamoDB table (that the role does have access to).
The role trust policy trusts the account it's in, and the account `stack2` is in (if it's different, which then must be passed in as a parameter).

`stack2` contains four Lambda functions, all using the same role. This function role has permission to assume the role in `stack1`.
The stack requires as input the role ARN, the bucket name, and the table name.

Each of the four functions has the same logic: assume the role, and attempt to get an object from the bucket and a record from the table.
The output is the result for each operation.
As the policy on the role does not allow the S3 operation, it will return "Access denied!" as the result.

## Running

Run `test.py`, providing `--stack1-profile` and `--stack2-profile` if you used those on `deploy.py`.
This will put a timestamp as the data under the keys `Function1` through `Function4` in both the bucket and the table.
The output of each Lambda function should be something like this:
```json
{
  "lambda_role_arn": "arn:aws:sts::123456789012:assumed-role/aws-assume-role-lib-demo-stack2-FunctionRole-ABC123XYZ/aws-assume-role-lib-demo-stack2-Function1-DEF456UVW",
  "assumed_role_arn": "arn:aws:sts::567890123456:assumed-role/aws-assume-role-lib-demo-stack1-Role-GHI789RST/aws-assume-role-lib-demo-stack2-Function1-DEF456UVW",
  "use_source_identity": true,
  "s3": "No permissions!",
  "ddb": {
    "content": "2021-09-21T23:57:53.838694+00:00",
    "pk": "Function1"
  }
}
```
at the end of the test, the data is deleted.

The functions progress from the most naïve implementation of role assumption for Lambda functions to the most compact, using `aws-assume-role-lib`.

### Error handling in the functions
The functions use [`aws-error-utils`](https://github.com/benkehoe/aws-error-utils) to catch the access denied exceptions.
Instead of this:
```python
try:
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=KEY,
    )
    s3_result = response['Body'].read()
except botocore.exceptions.ClientError as e:
    if e.response["Error"]["Code"] == "AccessDenied":
        s3_result = "Access denied!"
    else:
        s3_result = str(e)
except Exception as e:
    s3_result = str(e)
```

we get to write this:
```python
from aws_error_utils import errors

try:
    response = s3.get_object(
        Bucket=BUCKET_NAME,
        Key=KEY,
    )
    s3_result = response['Body'].read()
except errors.AccessDenied:
    s3_result = "Access denied!"
except Exception as e:
    s3_result = str(e)
```
Note that while the `S3.GetObject` API call uses `AccessDenied` as its error code, `DynamoDB.GetItem` uses `AccessDeniedException`.
Always check the service docs for the error codes (and click the feedback button in the upper right corner of the docs page if the error codes aren't documented!).

### Function1: the naïve implementation
[**View the function source here**](src/handler1.py)

In Function1, an STS client is created using the module-level `boto3.client()` function inside the handler function.
This client is used to make the `AssumeRole` call in every invocation, and the returned credentials are directly used to create S3 and DynamoDB clients.

We need to explicitly set the `RoleSessionName` in the `AssumeRole` call, as it is a required parameter.

Note that we're making use of the `SourceIdentity` parameter in the `AssumeRole` call.
The `SourceIdentity` propagates through further `AssumeRole` calls.
It's a good practice to use this; while it doesn't matter for this case, if the assumed role itself had `AssumeRole` permissions, the `SourceIdentity` persists into that new session, allowing its origin to be traced back.
For more details, [check out the documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html).

### Function2: using sessions
[**View the function source here**](src/handler2.py)

In Function2, we clean this up a little bit by using boto3 Sessions.
For more details on sessions and why you should use them, read [this article](https://ben11kehoe.medium.com/boto3-sessions-and-why-you-should-use-them-9b094eb5ca8e).

Inside the handler, we create a default session, which will pick up the Lambda function's credentials, and use it to create the STS client.
We still call `AssumeRole` from inside the handler every invocation.
We use the returned credentials to create the assumed role session, and create the S3 and DynamoDB clients from that new session.

### Function3: reusing sessions between invocations
[**View the function source here**](src/handler3.py)

We know that the credentials for the Lambda function instance are valid for the life of the instance, and we know that the credentials returned by the `AssumeRole` call don't expire immediately (in fact, the minimum lifetime of assumed-role credentials is 900 seconds, that is, 15 minutes).
So in Function3, we move the role assumption code to the initialization, outside of the handler function.

However, the assumed role credentials may expire before the function instance is discarded, and then when we make the S3 and DynamoDB calls during an invocation, they would be using expired credentials.
We could implement our own caching scheme, calling `AssumeRole` from inside the handler when the credentials are expired.
But instead...

### Function4: `aws-assume-role-lib`
[**View the function source here**](src/handler4.py)

This is what `aws-assume-role-lib` is for.
The session returned by `aws_assume_role_lib.assume_role()` handles caching and refreshing transparently, using the mechanisms built in to `boto3`/`botocore`.

So now, when we create the assumed role session in the initialization code, we know that session will be valid for the life of the Lambda function instance.

We no longer need to provide `RoleSessionName`, because that's automatically generated for you if it's absent (again a built-in mechanism of `botocore`).
Or, if you're using `SourceIdentity`, `assume_role()` sets the `RoleSessionName` to the `SourceIdentity`.

For `SourceIdentity`, we are using the `aws_assume_role_lib.generate_lambda_session_name()` function, which can also be used for the `RoleSessionName` directly if you're not using `SourceIdentity`.
This function creates a session name, suitable for either `RoleSessionName` or `SourceIdentity`, that attempts to include the function name, version, and function instance identifier, for maximum traceability.

You can go into the CloudWatch Logs for Function4, and you'll see the log stream name matches the identifier included in the role session name.
Your role session name will be something like `aws-assume-role-lib-demo-stack2-Function4-ABC123XYZ.7dbe52557` and your log stream name will be something like `2021/10/02/[$LATEST]7dbe525574b94441ab09ec8ae6d724be`.
This can help you trace activity back from, say, a CloudTrail log to the CloudWatch Logs corresponding to the usage of those credentials.
