# Lab 1.2 - Users, Groups, Roles

**Date:** 2026-10-08
**Goal:** Understand the three IAM identity types, design a full Users/Groups/Roles setup, and validate effective permissions. Adapted mid-execution after encountering an organization-level Service Control Policy (SCP) blocking IAM write operations.

## Objective

1. Build an IAM Group with the S3 read-only policy attached
2. Add a User to the group and test inherited permissions
3. Create an IAM Role with a trust policy for EC2
4. Compare Users vs Groups vs Roles and understand when to use each

## The Blocker: Organization-Level SCP

During execution, `aws iam create-group` failed with this error:

User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform: iam:CreateGroup on resource: arn:aws:iam::803964124082:group/S3-Analysts with an explicit deny in a service control policy: arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

### What this means

- The account `803964124082` is a member account in AWS Organizations `o-g4oan97ai8`
- The management account is `321043732798`
- An SCP with ID `p-whl27g4i` is attached with explicit Deny statements
- SCPs evaluate before identity policies. An explicit Deny in an SCP cannot be overridden by any IAM policy in the member account

### Attempted remediation

1. Console Organizations returned "Access to this service is not supported"
2. CLI detach-policy with member account credentials returned AccessDeniedException
3. CLI detach-policy requires management account credentials, which were not available

Conclusion: the SCP cannot be removed from the member account. The lab was adapted to design-plus-document mode.

## Account Permission Survey

Which actions are allowed vs blocked by the SCP:

| Service / Action | Result | Notes |
|---|---|---|
| iam:ListUsers | allowed | Read works |
| iam:ListRoles | allowed | Read works |
| iam:CreateGroup | explicitDeny | SCP p-whl27g4i |
| s3:ListBuckets | allowed | |
| s3:CreateBucket | allowed | S3 write works |
| cloudtrail:DescribeTrails | allowed | |
| guardduty:ListDetectors | explicitDeny | SCP p-whl27g4i |
| kms:ListKeys | allowed | |
| config:DescribeConfigurationRecorders | allowed | |

Takeaway: the SCP is a targeted blocklist, not a full lockdown. IAM writes and GuardDuty are blocked; S3, KMS, CloudTrail, and Config are largely usable.

## Design Artifacts

### 1. The S3 Read-Only Policy

File: policies/s3-readonly-analyst.json

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListAllBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "ReadSpecificBucket",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::analyst-data-bucket",
        "arn:aws:s3:::analyst-data-bucket/*"
      ]
    }
  ]
}