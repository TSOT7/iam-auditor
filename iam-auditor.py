import boto3
from datetime import datetime, timezone

cli = boto3.client("iam")
response = cli.list_users()
users = response["Users"]

def check_wildcard_permissions(username):
    response = cli.list_attached_user_policies(UserName=username)

    for policy in response["AttachedPolicies"]:
        arn = policy["PolicyArn"]

        # live version label
        version_id = cli.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]

        # fetch rules
        version = cli.get_policy_version(PolicyArn=arn, VersionId=version_id)
        statements = version["PolicyVersion"]["Document"]["Statement"] # 3rd layer of PolicyVersion
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement["Effect"] != "Allow":
                continue

            actions = statement["Action"]
            resources = statement["Resource"]

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions or "*" in resources:
                return True

    return False

def check_mfa(username):
    mfaDevice = cli.list_mfa_devices(UserName=username)
    if(len(mfaDevice["MFADevices"]) > 0):
        return True
    else:
        return False

def check_access_keys(username):
    response = cli.list_access_keys(UserName=username)
    AccessKeyMeta = response["AccessKeyMetadata"]   

    for key in AccessKeyMeta:
        if (key["Status"] != "Active"):
            continue
        age = datetime.now(timezone.utc) - key["CreateDate"]
        if (age.days > 90):
            return True
    return False



