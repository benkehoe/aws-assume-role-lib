#!/usr/bin/env python3

import argparse
import os
import datetime
import json

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
parser.add_argument("--stack-name-prefix", default="aws-assume-role-lib-demo")
args = parser.parse_args()

stack1_session = boto3.Session(profile_name=args.stack1_profile)
stack2_session = boto3.Session(profile_name=args.stack2_profile)

stack1_cfn = stack1_session.client("cloudformation")
stack2_cfn = stack2_session.client("cloudformation")

stack1_name = f"{args.stack_name_prefix}-stack1"
stack2_name = f"{args.stack_name_prefix}-stack2"

response = stack1_cfn.describe_stacks(StackName=stack1_name)
_, _, stack1_outputs = get_stack_info(response)

response = stack2_cfn.describe_stacks(StackName=stack2_name)
_, _, stack2_outputs = get_stack_info(response)

print(f"Populating data to {stack1_name}")

timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
timestamp_str = timestamp.isoformat()
timestamp_bytes = timestamp_str.encode("utf-8")

bucket = stack1_session.resource("s3").Bucket(stack1_outputs["BucketName"])
table = stack1_session.resource("dynamodb").Table(stack1_outputs["TableName"])
for key in ["Function1", "Function2", "Function3", "Function4"]:
    bucket.put_object(Key=key, Body=timestamp_bytes)
    table.put_item(Item={
        "pk": key,
        "content": timestamp_str,
    })

lmda = stack2_session.client("lambda")

for key in ["Function1Name", "Function2Name", "Function3Name", "Function4Name"]:
    function_name = stack2_outputs[key]
    print(f"\n\nTesting {key}: {function_name}")
    response = lmda.invoke(FunctionName=function_name)
    try:
        payload = json.load(response["Payload"])
        print(json.dumps(payload, indent=2))
    except Exception as e:
        print(f"ERROR: {e}")

print("Deleting data")
keys = ["Function1", "Function2", "Function3", "Function4"]
bucket.delete_objects(
    Delete={
        "Objects": [{"Key": key} for key in keys]
    }
)
for key in keys:
    table.delete_item(Key={"pk": key})
