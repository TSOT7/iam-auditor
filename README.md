# IAM Auditor

A Python CLI that scans every IAM user in an AWS account for common security misconfigurations and reports them by severity.

## What it checks

| Check | Severity |
|---|---|
| Console access without MFA | HIGH |
| Policy grants `*` on `*` (full admin), or uses `Allow` + `NotAction` | HIGH |
| Policy grants `*` on specific resources, or a service-wide action like `s3:*` on all resources | MEDIUM |
| Active access key older than 90 days | MEDIUM |
| Active access key never used | LOW |

Policies are checked from all sources: managed and inline policies on the user, and on every group the user belongs to.

## Usage

```
pip install -r requirements.txt
python iam-auditor.py
```

Requires AWS credentials with IAM read access.

