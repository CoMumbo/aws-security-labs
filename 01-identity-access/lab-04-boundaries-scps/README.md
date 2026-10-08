# Lab 1.4 - Permission Boundaries and SCPs

**Date:** 2026-10-08
**Goal:** Understand the full AWS policy evaluation chain, build a permissions boundary that limits an identity to S3 read-only, and prove the boundary effect using the AWS IAM policy simulator.

## Objective

1. Design an over-permissive identity policy (allow s3, ec2, and iam reads)
2. Design a permissions boundary that only allows S3 read
3. Simulate the combined effect and confirm the boundary caps the identity
4. Document the difference between SCPs and permissions boundaries

## Concept: Policy Evaluation Chain

Every authorization decision passes through multiple layers:

1. SCP (org-level guardrail)
2. Resource-based policy (e.g., S3 bucket policy)
3. Identity-based policy (attached to the user/role)
4. Permissions boundary (ceiling for that identity)
5. Session policy (passed during AssumeRole)

Decision logic:

- Any layer returning an explicit Deny -> request denied
- Otherwise, every relevant layer must Allow for the request to succeed
- If no layer explicitly allows -> implicit deny

### SCP vs Permissions Boundary

| Aspect | SCP | Permissions Boundary |
|---|---|---|
| Who applies it | AWS Organizations (management account) | IAM admin in the account |
| Scope | All principals in the account | One specific user or role |
| Purpose | Organizational guardrail | Delegation ceiling |
| Visible from member account | No | Yes |

A permissions boundary does NOT grant permissions. It only caps them.

## Design Artifacts

### Over-permissive identity policy

File: policies/over-permissive-identity.json

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEverythingWeMightWant",
      "Effect": "Allow",
      "Action": ["s3:*", "ec2:*", "iam:ListUsers", "iam:ListRoles"],
      "Resource": "*"
    }
  ]
}