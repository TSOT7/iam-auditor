import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

cli = boto3.client("iam")

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def paginate(method, key, **kwargs): # loops page truncation logic 
    for page in cli.get_paginator(method).paginate(**kwargs):
        yield from page[key]


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (str, dict)):
        return [value]
    return value


def finding(severity, check, user, detail):
    return {"severity": severity, "check": check, "user": user, "detail": detail}


def get_user_policies(username):
    """Yield (source, policy_name, document) for every policy that applies to a user:
    attached + inline on the user, and attached + inline on each of their groups."""
    for policy in paginate("list_attached_user_policies", "AttachedPolicies", UserName=username):
        yield "user-attached", policy["PolicyName"], get_managed_policy_document(policy["PolicyArn"])

    for name in paginate("list_user_policies", "PolicyNames", UserName=username):
        doc = cli.get_user_policy(UserName=username, PolicyName=name)["PolicyDocument"]
        yield "user-inline", name, doc

    for group in paginate("list_groups_for_user", "Groups", UserName=username):
        group_name = group["GroupName"]
        for policy in paginate("list_attached_group_policies", "AttachedPolicies", GroupName=group_name):
            yield f"group:{group_name}", policy["PolicyName"], get_managed_policy_document(policy["PolicyArn"])

        for name in paginate("list_group_policies", "PolicyNames", GroupName=group_name):
            doc = cli.get_group_policy(GroupName=group_name, PolicyName=name)["PolicyDocument"]
            yield f"group-inline:{group_name}", name, doc


_policy_cache = {}


def get_managed_policy_document(arn):
    # the same managed policy is often attached to many users/groups, so only fetch it once
    if arn not in _policy_cache:
        version_id = cli.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
        version = cli.get_policy_version(PolicyArn=arn, VersionId=version_id)
        _policy_cache[arn] = version["PolicyVersion"]["Document"]
    return _policy_cache[arn]


def check_wildcard_permissions(username):
    findings = []

    for source, policy_name, document in get_user_policies(username):
        for statement in as_list(document.get("Statement")):
            if statement.get("Effect") != "Allow":
                continue

            where = f"{policy_name} ({source})"
            actions = as_list(statement.get("Action"))
            resources = as_list(statement.get("Resource"))

            if "NotAction" in statement:
                # Allow + NotAction grants everything except the listed actions
                findings.append(finding("HIGH", "wildcard", username, f"{where}: Allow with NotAction"))
                continue

            full_admin = "*" in actions
            service_admin = [a for a in actions if a.endswith(":*")]
            all_resources = "*" in resources or "NotResource" in statement

            if full_admin and all_resources:
                findings.append(finding("HIGH", "wildcard", username, f"{where}: Action '*' on Resource '*' (full admin)"))
            elif full_admin:
                findings.append(finding("MEDIUM", "wildcard", username, f"{where}: Action '*' on {resources}"))
            elif service_admin and all_resources:
                findings.append(finding("MEDIUM", "wildcard", username, f"{where}: {service_admin} on Resource '*'"))

    return findings


def has_console_access(username):
    try:
        cli.get_login_profile(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def check_mfa(username):
    # MFA only protects console sign-in, so users without a password are not flagged
    if not has_console_access(username):
        return []

    devices = list(paginate("list_mfa_devices", "MFADevices", UserName=username))
    if not devices:
        return [finding("HIGH", "mfa", username, "Console access enabled without MFA")]
    return []


def check_access_keys(username, max_age_days):
    findings = []
    now = datetime.now(timezone.utc)

    for key in paginate("list_access_keys", "AccessKeyMetadata", UserName=username):
        if key["Status"] != "Active":
            continue

        key_id = key["AccessKeyId"]
        age = (now - key["CreateDate"]).days

        last_used = cli.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"].get("LastUsedDate")
        last_used_text = f"last used {(now - last_used).days} days ago" if last_used else "never used"

        if age > max_age_days:
            findings.append(finding("MEDIUM", "access-key", username, f"{key_id} is {age} days old, {last_used_text}"))
        elif last_used is None and age > 7:
            findings.append(finding("LOW", "access-key", username, f"{key_id} is active but has never been used"))

    return findings


def audit(max_key_age):
    findings = []

    for user in paginate("list_users", "Users"):
        username = user["UserName"]
        try:
            findings += check_mfa(username)
            findings += check_access_keys(username, max_key_age)
            findings += check_wildcard_permissions(username)
        except ClientError as e:
            # one denied call shouldn't kill the whole audit
            findings.append(finding("LOW", "error", username, f"Could not audit: {e.response['Error']['Code']}"))

    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["user"]))


def print_report(findings):
    if not findings:
        print("No findings.")
        return

    for f in findings:
        print(f"[{f['severity']:<6}] {f['check']:<10} {f['user']:<20} {f['detail']}")

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    print(f"\n{len(findings)} findings: " + ", ".join(f"{n} {s}" for s, n in counts.items()))


def main():
    parser = argparse.ArgumentParser(description="Audit IAM users for MFA, stale access keys, and over-broad policies.")
    parser.add_argument("--max-key-age", type=int, default=90, help="flag active access keys older than this many days (default 90)")
    parser.add_argument("--json", action="store_true", help="output findings as JSON")
    args = parser.parse_args()

    findings = audit(args.max_key_age)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings)

    # non-zero exit when there are HIGH findings, so this can gate a CI pipeline
    sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
