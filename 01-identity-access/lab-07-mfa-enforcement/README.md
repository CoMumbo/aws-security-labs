# Lab 1.7 - MFA Enforcement

**Date:** 2026-10-09
**Goal:** Understand how to enforce MFA in AWS IAM policies using the aws:MultiFactorAuthPresent and aws:MultiFactorAuthAge condition keys, and prove the enforcement logic using the IAM policy simulator.

## Objective

1. Design a "deny all without MFA" policy that still allows MFA setup
2. Design a time-limited MFA policy (require MFA within the last 15 minutes)
3. Validate both policies with Access Analyzer
4. Prove the enforcement logic with the simulator across four scenarios

## Concept: MFA in IAM Policies

IAM policies can require MFA via two condition keys:

| Condition Key | Meaning |
|---|---|
| aws:MultiFactorAuthPresent | True if the request was signed with MFA |
| aws:MultiFactorAuthAge | Seconds since MFA was last verified |

### Why BoolIfExists

Plain Bool only matches when the key exists. Long-lived access keys (AKIA) do not carry MFA context, so the key is entirely absent for these credentials. Using Bool would skip the condition, defeating the purpose.

BoolIfExists treats a missing key as false, which is exactly what we want: any request without proven MFA is caught.

### The MFA Setup Exception

A naive "deny all without MFA" policy locks a user out permanently, because they can never enable MFA in the first place. The policy must NOT deny the small set of actions required to set up MFA:

- iam:CreateVirtualMFADevice
- iam:EnableMFADevice
- iam:GetUser
- iam:ListMFADevices
- iam:ResyncMFADevice
- sts:GetSessionToken

These go in a NotAction list. Everything else is denied when MFA is absent.

## Current Account MFA State

From aws iam get-account-summary:

- AccountMFAEnabled: 0 (root user does not have MFA)
- MFADevices: 0
- MFADevicesInUse: 0
- AccountAccessKeysPresent: 0
- AccountPasswordPresent: 0

From aws iam list-mfa-devices --user-name admin-zeff:

- Empty list. The admin-zeff user has no MFA device configured.

## Design Artifacts

### Policy 1 - Deny All Without MFA

File: policies/deny-without-mfa.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptMFASetup",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}

### Policy 2 - Deny If MFA Is Stale

File: policies/deny-stale-mfa.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIfMFAStale",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "aws:MultiFactorAuthAge": "900"
        }
      }
    }
  ]
}

This requires MFA to have been verified within the last 900 seconds (15 minutes). After that, everything is denied until the user re-authenticates.

## Validation

### Access Analyzer

Both policies were validated with:

aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policies/deny-without-mfa.json
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policies/deny-stale-mfa.json

Result for both: {"findings": []} - clean, no structural issues.

Note: the first attempt returned JSON_SYNTAX_ERROR at line 1 column 0 due to a UTF-8 BOM prepended by PowerShell Out-File -Encoding utf8. Fixing this required rewriting the files with [System.IO.File]::WriteAllText, which does not add a BOM. This is the same Windows CLI gotcha documented in Lab 1.4.

### Simulator Tests

Four scenarios were run using aws iam simulate-custom-policy --cli-input-json, varying the policy combination and the MFA context value.

| Test | Policies | MFA Present | EvalDecision |
|---|---|---|---|
| 1 | Deny only | false | explicitDeny |
| 2 | Deny only | true | implicitDeny |
| 3 | Allow + Deny | false | explicitDeny |
| 4 | Allow + Deny | true | allowed |

### Interpretation

- Test 1: the Deny statement matches because MFA is absent. Result: explicitDeny.
- Test 2: the Deny condition is not satisfied (MFA is present), and there is no Allow statement in this policy, so the result is implicitDeny. The policy alone grants nothing; it only removes permissions.
- Test 3: the Allow-All policy would grant s3:DeleteBucket, but the MFA Deny policy explicitly denies it. MatchedStatements points to PolicyInputList.2 (the Deny). Result: explicitDeny. Explicit deny wins over allow, always.
- Test 4: MFA is present, the Deny condition is not satisfied, and the Allow-All policy grants the action. Result: allowed.

This proves both the MFA enforcement mechanism and the "explicit deny wins" rule simultaneously.

## Lessons / Gotchas

1. Deny-only policies grant nothing. A "deny all without MFA" policy is not a permission policy; it is an enforcement layer that must be paired with a separate Allow policy (typically a managed policy).

2. BoolIfExists is required, not optional. Plain Bool skips the condition when the MFA context key is absent (which is the case for long-lived access keys). BoolIfExists treats missing as false, which is the safe default.

3. The MFA setup exception is critical. A policy that denies everything without MFA must whitelist MFA setup actions in NotAction, or users can never enable MFA.

4. Simulator ContextEntries can inject MFA state. The --context-entries flag (or the ContextEntries field in --cli-input-json) lets you simulate both MFA-present and MFA-absent scenarios against the same policy.

5. Time-limited MFA adds defense in depth. Requiring MFA within the last 15 minutes (aws:MultiFactorAuthAge <= 900) limits the window in which a stolen session token is useful.

6. BOM again. PowerShell Out-File -Encoding utf8 prepends a BOM that breaks AWS CLI JSON parsing. Use [System.IO.File]::WriteAllText for JSON files.

## Files

- policies/deny-without-mfa.json - MFA enforcement policy
- policies/deny-stale-mfa.json - time-limited MFA policy
- cli-test-01.json through cli-test-04.json - reproducible simulator scenarios

## Real-World Application

MFA enforcement policies are the standard way enterprises enforce second-factor authentication without relying solely on IdP-level controls. Common patterns:

- Baseline requirement: every IAM user in the account has the "deny all without MFA" policy attached, so even a leaked password cannot be used without the second factor
- Privileged action gating: sensitive operations (iam:*, s3:DeleteBucket, kms:ScheduleKeyDeletion, organizations:*) require MFA regardless of user baseline
- Session freshness: financial and healthcare compliance frameworks often require MFA within the last 15 minutes for privileged actions, implemented via aws:MultiFactorAuthAge

These policies are also what enable the Identity Center / federation model to inherit MFA guarantees from the IdP: the MFA-present condition is satisfied by the federated session, so downstream policies that require MFA work seamlessly.
