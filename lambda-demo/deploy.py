#!/usr/bin/env python3

import subprocess
import argparse
import sys
import os
from pathlib import Path

import boto3

def get_stack_info(response, *, assert_params=None, assert_outputs=None):
    stacks = [stack for stack in response["Stacks"] if "DeletionTime" not in stack]
    assert len(stacks) == 1

    stack = stacks[0]

    parameters = {}
    for parameter in stack.get("Parameters", []):
        parameters[parameter["ParameterKey"]] = parameter["ParameterValue"]
    if assert_params:
        for param_name in assert_params:
            assert param_name in parameters, f"{param_name} is not in stack parameters!"

    outputs = {}
    for output in stack.get("Outputs", []):
        outputs[output["OutputKey"]] = output["OutputValue"]
    if assert_outputs:
        for output_name in assert_outputs:
            assert output_name in outputs, f"{output_name} is not in stack outputs!"

    return stack, parameters, outputs

parser = argparse.ArgumentParser()
parser.add_argument("--stack1-profile")
parser.add_argument("--stack2-profile")
parser.add_argument("--trust-account")
parser.add_argument("--stack-name-prefix", default="aws-assume-role-lib-demo")
parser.add_argument("--use-source-identity", choices=["true", "false"], default="true")
parser.add_argument("--bucket-access", choices=["Allow", "Deny"], default="Deny")
parser.add_argument("--table-access", choices=["Allow", "Deny"], default="Allow")
args = parser.parse_args()

directory = Path(sys.argv[0]).parent

stack1_session = boto3.Session(profile_name=args.stack1_profile)
stack2_session = boto3.Session(profile_name=args.stack2_profile)

stack1_account = stack1_session.client("sts").get_caller_identity()["Account"]
stack2_account = stack2_session.client("sts").get_caller_identity()["Account"]

stack1_cfn = stack1_session.client("cloudformation")
stack2_cfn = stack2_session.client("cloudformation")

stack1_creds = stack1_session.get_credentials().get_frozen_credentials()
stack1_env = os.environ.copy()
stack1_env.update({
    "AWS_ACCESS_KEY_ID": stack1_creds.access_key,
    "AWS_SECRET_ACCESS_KEY": stack1_creds.secret_key,
    "AWS_DEFAULT_REGION": stack1_session.region_name,
})
if stack1_creds.token:
    stack1_env["AWS_SESSION_TOKEN"] = stack1_creds.token

stack2_creds = stack2_session.get_credentials().get_frozen_credentials()
stack2_env = os.environ.copy()
stack2_env.update({
    "AWS_ACCESS_KEY_ID": stack2_creds.access_key,
    "AWS_SECRET_ACCESS_KEY": stack2_creds.secret_key,
    "AWS_DEFAULT_REGION": stack2_session.region_name,
})
if stack2_creds.token:
    stack2_env["AWS_SESSION_TOKEN"] = stack2_creds.token

stack1_name = f"{args.stack_name_prefix}-stack1"
stack2_name = f"{args.stack_name_prefix}-stack2"

stack1_parameter_dict = {
    "BucketAccess": args.bucket_access,
    "TableAccess": args.table_access,
}

if args.trust_account:
    stack1_parameter_dict["AccountToTrust"] = args.trust_account
elif stack1_account != stack2_account:
    stack1_parameter_dict["AccountToTrust"] = stack2_account

stack1_parameters = " ".join(f"{key}={value}" for key, value in stack1_parameter_dict.items())

stack1_deploy_args = [
    "sam", "deploy",
    "--template-file", "template1.yaml",
    "--stack-name", stack1_name,
    "--capabilities", "CAPABILITY_IAM",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides", stack1_parameters,
]

print("Deploying stack 1")
result = subprocess.run(stack1_deploy_args, env=stack1_env, cwd=directory, check=True)

stack2_build_args = [
    "sam", "build",
    "--template-file", "template2.yaml",
]

response = stack1_cfn.describe_stacks(StackName=stack1_name)

_, _, stack1_outputs = get_stack_info(response)

print("Building stack 2")
result = subprocess.run(stack2_build_args, env=stack2_env, cwd=directory, check=True)

stack2_parameter_dict = {
    "UseSourceIdentity": args.use_source_identity,
}
stack2_parameter_dict.update(stack1_outputs)
stack2_parameters = " ".join(f"{key}={value}" for key, value in stack2_parameter_dict.items())

stack2_deploy_args = [
    "sam", "deploy",
    "--template-file", ".aws-sam/build/template.yaml",
    "--stack-name", stack2_name,
    "--capabilities", "CAPABILITY_IAM",
    "--no-fail-on-empty-changeset",
    "--resolve-s3",
    "--parameter-overrides", stack2_parameters,
]

print("Deploying stack 2")
result = subprocess.run(stack2_deploy_args, env=stack2_env, cwd=directory, check=True)

response = stack2_cfn.describe_stacks(StackName=stack2_name)

_, _, stack2_outputs = get_stack_info(response)
