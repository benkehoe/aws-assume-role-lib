from .aws_assume_role_lib import (
    __version__,
    assume_role,
    get_role_arn,
    get_assumed_role_session_arn,
    generate_lambda_session_name,
    patch_boto3,
    JSONFileCache,
    AUTOMATIC_ROLE_SESSION_NAME,
)
