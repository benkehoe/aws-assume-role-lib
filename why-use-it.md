# Why you should use aws-assume-role-lib

## The usual approach
```python
role_arn = "arn:aws:iam::123456789012:role/MyRole"
session = boto3.Session()

sts = session.client("sts")
response = sts.assume_role(
    RoleArn=role_arn,
    RoleSessionName="something_you_have_decide_on"
)

credentials = response["Credentials"]

assumed_role_session = boto3.Session(
    aws_access_key_id=credentials["AccessKeyId"],
    aws_secret_access_key=credentials["SecretAccessKey"],
    aws_session_token=credentials["SessionToken"]
)

# use the session
print(assumed_role_session.client("sts").get_caller_identity())
```
Also note this doesn't handle keeping track of when the credentials expire to refresh them.

If you've only used `boto3.client()` and are not familiar with boto3 sessions, [here's an explainer](https://ben11kehoe.medium.com/boto3-sessions-and-why-you-should-use-them-9b094eb5ca8e).

## With aws-assume-role-lib
```python
role_arn = "arn:aws:iam::123456789012:role/MyRole"
session = boto3.Session()

assumed_role_session = aws_assume_role_lib(session, role_arn)

# use the session
print(assumed_role_session.client("sts").get_caller_identity())
```
Refreshing expired credentials is handled, and a role session name is generated for you (unless you want to provide one, of course).

[Go back to the main docs](README.md)
