# Lab 1.1 - IAM Policies from the Ground Up

**Date:** 2026-10-08
**Goal:** Write and validate a scoped IAM policy for a hypothetical S3 read-only analyst.

---

## Objective

Build a customer-managed IAM policy that grants read-only S3 access to a single bucket, attach it to a test user, and validate the effective permissions using the AWS CLI policy simulator.

---

## What I Built

A customer-managed IAM policy (`S3ReadOnlyAnalyst`) that:
- Allows listing all buckets (account-level action, unscoped)
- Allows reading objects only from `analyst-data-bucket`
- Denies everything else (implicit)

Attached to a test user `test-analyst` in account `803964124082`.

### The Policy JSON

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
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::analyst-data-bucket",
        "arn:aws:s3:::analyst-data-bucket/*"
      ]
    }
  ]
}
```

---

## Setup Commands

### 1. Create the policy

```bash
aws iam create-policy \
  --policy-name S3ReadOnlyAnalyst \
  --policy-document file://policies/s3-readonly-analyst.json \
  --description "Read-only access to analyst-data-bucket"
```

**Output:**
```json
"Arn": "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"
```

### 2. Create the test user

```bash
aws iam create-user --user-name test-analyst
```

### 3. Attach the policy to the user

```bash
aws iam attach-user-policy \
  --user-name test-analyst \
  --policy-arn "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"
```

### 4. Verify attachment

```bash
aws iam list-attached-user-policies --user-name test-analyst
```

**Output:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "S3ReadOnlyAnalyst",
            "PolicyArn": "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"
        }
    ]
}
```

---

## Key Concepts Learned

- **Deny always wins** over Allow
- `s3:ListBucket` operates on the bucket ARN (`arn:aws:s3:::bucket`)
- `s3:GetObject` operates on the object ARN (`arn:aws:s3:::bucket/*`)
- Account-level actions like `s3:ListAllMyBuckets` cannot be resource-scoped
- Policy Simulator (and CLI `simulate-principal-policy`) let you test policies without deploying

---

## Validation with the CLI Policy Simulator

### Test 1: ListAllMyBuckets

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::803964124082:user/test-analyst" \
  --action-names "s3:ListAllMyBuckets"
```

**Output:**
```json
{
    "EvaluationResults": [
        {
            "EvalActionName": "s3:ListAllMyBuckets",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {
                    "SourcePolicyId": "S3ReadOnlyAnalyst",
                    "SourcePolicyType": "IAM Policy",
                    "StartPosition": { "Line": 3, "Column": 17 },
                    "EndPosition": { "Line": 9, "Column": 6 }
                }
            ],
            "OrganizationsDecisionDetail": {
                "AllowedByOrganizations": true
            }
        }
    ]
}
```

**Result:** allowed (as expected). The matched statement points to `ListAllBuckets`.

### Test 2: DeleteObject

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::803964124082:user/test-analyst" \
  --action-names "s3:DeleteObject" \
  --resource-arns "arn:aws:s3:::analyst-data-bucket/test.txt"
```

**Output:**
```json
{
    "EvaluationResults": [
        {
            "EvalActionName": "s3:DeleteObject",
            "EvalResourceName": "arn:aws:s3:::analyst-data-bucket/test.txt",
            "EvalDecision": "explicitDeny",
            "MatchedStatements": [],
            "OrganizationsDecisionDetail": {
                "AllowedByOrganizations": false
            }
        }
    ]
}
```

**Result:** explicitDeny (unexpected - I expected implicitDeny).

### Test 3: GetObject on the target bucket

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::803964124082:user/test-analyst" \
  --action-names "s3:GetObject" \
  --resource-arns "arn:aws:s3:::analyst-data-bucket/secret.pdf"
```

**Result:** explicitDeny (unexpected - this should have been allowed by the policy).

### Test 4: GetObject on a different bucket

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::803964124082:user/test-analyst" \
  --action-names "s3:GetObject" \
  --resource-arns "arn:aws:s3:::some-other-bucket/file.txt"
```

**Result:** explicitDeny.

### Summary Table

| Test | Action | Resource | Expected | Actual |
|---|---|---|---|---|
| 1 | `s3:ListAllMyBuckets` | `*` | allowed | allowed |
| 2 | `s3:DeleteObject` | `analyst-data-bucket/test.txt` | implicitDeny | explicitDeny |
| 3 | `s3:GetObject` | `analyst-data-bucket/secret.pdf` | allowed | explicitDeny |
| 4 | `s3:GetObject` | `some-other-bucket/file.txt` | implicitDeny | explicitDeny |

---

## Unexpected Finding: Organization-Level SCP

Tests 2-4 returned `explicitDeny` instead of the expected `implicitDeny` (and Test 3 should have been `allowed`). This meant an explicit Deny statement was overriding the policy from somewhere.

### Diagnostic Steps

**Check 1 - Permissions boundary on the user:**
```bash
aws iam get-user --user-name test-analyst
```
Result: No `PermissionsBoundary` field present.

**Check 2 - Inline policies on the user:**
```bash
aws iam list-user-policies --user-name test-analyst
```
Result: `"PolicyNames": []`

**Check 3 - Group memberships:**
```bash
aws iam list-groups-for-user --user-name test-analyst
```
Result: `"Groups": []`

**Check 4 - Attached managed policies:**
```bash
aws iam list-attached-user-policies --user-name test-analyst
```
Result: Only `S3ReadOnlyAnalyst`.

**Check 5 - Organizations lookup:**
```bash
aws organizations describe-organization
```

**Output:**
```json
{
    "Organization": {
        "Id": "o-g4oan97ai8",
        "Arn": "arn:aws:organizations::321043732798:organization/o-g4oan97ai8",
        "FeatureSet": "ALL",
        "MasterAccountArn": "arn:aws:organizations::321043732798:account/o-g4oan97ai8/321043732798",
        "MasterAccountId": "321043732798",
        "MasterAccountEmail": "zeffcollins@gmail.com",
        "AvailablePolicyTypes": [
            {
                "Type": "SERVICE_CONTROL_POLICY",
                "Status": "ENABLED"
            }
        ]
    }
}
```

### What This Tells Us

- The account `803964124082` is a **member account** in AWS Organizations `o-g4oan97ai8`
- The **management account** is `321043732798`
- **Service Control Policies (SCPs) are enabled** on the organization
- `organizations:ListAccounts` was denied for the current user, so the specific SCP could not be inspected

### Root Cause

An **SCP attached at the organization level** is applying an explicit Deny for S3 actions that overrides the identity-based policy. The `OrganizationsDecisionDetail: { "AllowedByOrganizations": false }` field in the simulator output is the tell.

---

## Lessons / Gotchas

1. **Explicit denies can originate outside your account.** SCPs, permissions boundaries, and resource policies can all override your IAM policies - and you may not have visibility into them.
2. **`OrganizationsDecisionDetail` in simulator output is the key signal** for org-level denies.
3. **Member accounts inherit org guardrails.** Even with `AdministratorAccess`, an SCP can cap what you're allowed to do.
4. **In real cloud security, visibility matters.** A member account that can't inspect its own effective permissions is a governance problem.
5. **Policy simulation with `--resource-arns`** helps narrow down whether a deny is action-scoped or resource-scoped.

---

## Cleanup Commands

```bash
aws iam detach-user-policy \
  --user-name test-analyst \
  --policy-arn "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"

aws iam delete-user --user-name test-analyst

aws iam delete-policy \
  --policy-arn "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"
```

---

## Files

- `policies/s3-readonly-analyst.json` - the policy
- `setup.sh` - reproducible via AWS CLI
- `screenshots/` - Policy Simulator / CLI evidence

---

## Real-World Application

This mirrors real IAM debugging: an engineer builds a policy that looks correct, tests it, gets denied - and must trace the deny through the entire policy evaluation chain (identity policies -> boundaries -> SCPs -> resource policies). Knowing to check `OrganizationsDecisionDetail` saves hours.

It also highlights why **org-level observability** matters: a member account that can't inspect its own effective permissions is a governance problem. Security teams should ensure appropriate read access to Organizations for the people who need to debug access issues.