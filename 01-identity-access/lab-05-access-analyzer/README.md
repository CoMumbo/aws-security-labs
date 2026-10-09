# Lab 1.5 - IAM Access Analyzer

**Date:** 2026-10-09
**Goal:** Understand Access Analyzer, its role in finding unintended external access, and its policy validation API. Adapted mid-lab after the analyzer management APIs were found to be blocked by an SCP.

## Objective

1. Understand Access Analyzer's purpose and zones of trust
2. Attempt to create an analyzer and view findings
3. Probe which Access Analyzer APIs still work under the SCP
4. Validate IAM policies across all four policy types using the validate-policy API
5. Document the boundary between what is and is not possible in this account

## Concept: What Access Analyzer Does

Access Analyzer analyzes resource-based policies on S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, SNS topics, Secrets Manager secrets, and EFS file systems. It compares what those policies allow against a defined zone of trust.

Zones of trust:

- Account - only this AWS account is trusted
- Organization - every account in the AWS Org is trusted
- Internet - stricter mode where only explicitly trusted external entities are not flagged

Findings flag resources reachable by principals outside the zone of trust.

## The SCP Blocker

The list-analyzers call was rejected:

User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to
perform: access-analyzer:ListAnalyzers on resource:
arn:aws:access-analyzer:eu-north-1:803964124082:* with an explicit deny
in a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

The same SCP (p-whl27g4i) that blocked IAM writes and GuardDuty also blocks Access Analyzer management APIs.

## What Still Works: validate-policy

The validate-policy API is not blocked. It runs policy checks against IAM action and resource catalogues plus best-practice rules. It works for all four policy types.

### Test 1 - Resource policy with bad ARN

File: policies/bad-resource-arn.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BadResource",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "not-a-valid-arn"
    }
  ]
}

Command:

aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY --policy-document file://policies/bad-resource-arn.json

Findings:

- MISSING_PRINCIPAL (ERROR) - Add a Principal element to the policy statement.
- MISSING_ARN_FIELD (ERROR) - ARNs must have at least 6 fields: arn:partition:service:region:account:resource.

### Test 2 - Resource policy with typo action

File: policies/typo-action.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObjekt",
      "Resource": "*"
    }
  ]
}

Findings for RESOURCE_POLICY:

- MISSING_PRINCIPAL
- INVALID_ACTION - s3:GetObjekt does not exist.

Findings for IDENTITY_POLICY:

- INVALID_ACTION only. Identity policies do not require a Principal element.

Findings for SERVICE_CONTROL_POLICY:

- INVALID_ACTION only.

### Test 3 - Wildcard principal (valid but risky)

File: policies/wildcard-principal.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}

Findings: none (empty array).

validate-policy checks structure and validity, not security posture. A wildcard principal policy passes validation because it is syntactically correct. Detecting that it is risky requires the analyzer's findings feature, which is SCP-blocked in this account.

### Test 4 - Valid resource policy

File: policies/valid-resource-policy.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSpecificAccountRead",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}

Result: {"findings": []} - clean.

## Test Summary

| # | Policy | Policy Type | Findings |
|---|---|---|---|
| 1 | bad-resource-arn.json | RESOURCE_POLICY | MISSING_PRINCIPAL, MISSING_ARN_FIELD |
| 2 | typo-action.json | RESOURCE_POLICY | MISSING_PRINCIPAL, INVALID_ACTION |
| 3 | typo-action.json | IDENTITY_POLICY | INVALID_ACTION |
| 4 | typo-action.json | SERVICE_CONTROL_POLICY | INVALID_ACTION |
| 5 | wildcard-principal.json | RESOURCE_POLICY | (none) |
| 6 | valid-resource-policy.json | RESOURCE_POLICY | (none) |

## Lessons / Gotchas

1. Two distinct features. Access Analyzer has (a) deployed-resource scanning that produces findings about external access, and (b) policy validation APIs that check policies before deployment. They are separate and can be independently blocked.

2. validate-policy is structural, not behavioral. It confirms an action exists, an ARN is well-formed, and required fields are present. It does not evaluate whether a policy is secure. Wildcard principals pass validation.

3. Different policy types have different required fields. Resource policies require Principal. Identity policies do not. The same typo policy produced different finding sets depending on the --policy-type argument.

4. Findings that block a lab are findings worth documenting. The SCP block (p-whl27g4i) is now referenced in three labs (1.2, 1.4, 1.5) with increasing specificity. This is realistic enterprise work: some security services are centrally controlled.

5. validate-policy can be run in CI/CD. Because it does not require a deployed analyzer, it can be called on PRs and commits to catch IAM policy mistakes before merge.

6. Windows CLI quirks. The --access file:// flag for check-access-not-granted rejected both inline JSON (PowerShell quote mangling) and file:// (encoding). Use --cli-input-json for complex request bodies on Windows. This is the same pattern observed in Lab 1.4.

## Files

- policies/bad-resource-arn.json
- policies/typo-action.json
- policies/wildcard-principal.json
- policies/valid-resource-policy.json
- policies/public-bucket-policy.json
- access-check.json

## Real-World Application

Access Analyzer's policy validation is one of the few IAM security tools that works without external dependencies or deployed infrastructure. In enterprise environments, it is commonly wired into:

- CI/CD pipelines: validate every IAM policy PR before merge
- IaC workflows: validate CloudFormation/Terraform-generated policies
- Governance gates: block deploys that introduce MISSING_PRINCIPAL, INVALID_ACTION, or malformed ARNs

The deployed-resource scanning feature catches a different class of problem: resources that are live but unexpectedly reachable from outside the account/org. Both features serve security; both should be used where available.
