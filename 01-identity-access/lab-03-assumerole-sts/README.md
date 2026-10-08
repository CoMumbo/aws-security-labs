# Lab 1.3 - AssumeRole and STS

**Date:** 2026-10-08
**Goal:** Understand role assumption, temporary credentials, and the Security Token Service (STS). Build a real role and assume it via the CLI to obtain temporary credentials.

## Objective

1. Design a trust policy that allows a specific IAM user to assume a role
2. Design a permission policy for the role (S3 read-only)
3. Create the role and attach the permission policy
4. Assume the role using `aws sts assume-role`
5. Prove identity changed and that least privilege applies

## Concept: How AssumeRole Works

Every role has two policy types:

- **Trust policy** (assume role policy): Defines who may assume the role
- **Permission policy**: Defines what the role can do once assumed

For a role to be assumed by a caller, BOTH must be true:

1. The role's trust policy allows the caller to call sts:AssumeRole
2. The caller's own identity policy allows sts:AssumeRole on the target role

If either side denies, the call fails.

## Design Artifacts

### Trust Policy

File: policies/analyst-trust-policy.json

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAdminZeffToAssume",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::803964124082:user/admin-zeff"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}