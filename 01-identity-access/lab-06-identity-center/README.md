# Lab 1.6 - IAM Identity Center (SSO)

**Date:** 2026-10-09
**Goal:** Understand IAM Identity Center as the modern pattern for human access to AWS, and probe its availability in this account. Adapted mid-lab after CreateInstance was found to be blocked by an organization-level SCP.

## Objective

1. Understand what Identity Center replaces (IAM users for humans)
2. Learn the identity flow: IdP -> Identity Center -> Permission Set -> Role
3. Probe which Identity Center APIs work in this account
4. Document the second SCP discovered during this lab

## Concept: What IAM Identity Center Is

Identity Center (formerly AWS SSO) is the centralized service for giving humans access to AWS accounts and applications. It replaces the legacy pattern of creating one IAM user per person per account.

The modern pattern:
Human -> Identity Provider (Okta/Azure AD/Google/IdC directory)
-> Identity Center
-> Permission Set (attached to account)
-> Temporary role session

text

Key components:

- **Identity source** - either Identity Center's built-in directory or an external IdP
- **Permission set** - a reusable bundle of IAM policies that becomes a role in each target account
- **Assignment** - links a user/group + permission set + account
- **Portal** - the URL users log into to pick an account and get a role session

### Why It Replaces IAM Users

| Aspect | IAM User | Identity Center |
|---|---|---|
| Credentials | Long-lived password + access keys | Federated session, temporary |
| Per-account setup | Manual per account | Centralized |
| Password management | Per account | Central IdP |
| Audit trail | Separate per account | Unified |
| Best practice in 2024+ | Discouraged for humans | Preferred for humans |

AWS now actively recommends Identity Center (or a direct IdP federation) over IAM users for human access.

## The SCP Blocker

Attempting to create an Identity Center instance:
aws sso-admin create-instance

text

Result:
User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to
perform: sso:CreateInstance on resource: arn:aws:sso:::instance/*
with an explicit deny in a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-83yq4wr7

text

Note the SCP ID: **p-83yq4wr7**. This is different from the SCP that blocked IAM/GuardDuty/Access Analyzer (p-whl27g4i). The organization applies at least two SCPs, each targeting different service families.

## API Probe Results

| API | Result | Interpretation |
|---|---|---|
| sso-admin list-instances | allowed, empty list | Not blocked |
| sso-admin create-instance | explicitDeny via SCP p-83yq4wr7 | Blocked |
| sso-admin list-permission-sets | validation error (bad ARN format) | Not blocked |
| sso-admin list-applications | resource does not exist | Not blocked, just no instance |
| sso-admin create-permission-set | identity denied | Not SCP-blocked; no instance to target |
| identitystore list-users | resource does not exist | Not blocked, just no identity store |
| organizations list-policies | AccessDenied | No visibility from member account |
| organizations describe-organization | allowed | Read of org metadata permitted |

## Full SCP Discovery Map (across labs 1.2, 1.5, 1.6)

| Service / Action | Result | Source |
|---|---|---|
| iam:CreateGroup | explicit deny | SCP p-whl27g4i |
| iam:CreateRole | allowed | - |
| guardduty:* | explicit deny | SCP p-whl27g4i |
| access-analyzer:ListAnalyzers | explicit deny | SCP p-whl27g4i |
| access-analyzer:ValidatePolicy | allowed | - |
| sso:CreateInstance | explicit deny | SCP p-83yq4wr7 |
| sso-admin:ListInstances | allowed | - |
| identitystore:ListUsers | not blocked (no resource) | - |
| organizations:DescribeOrganization | allowed | - |
| organizations:ListPolicies | denied | member account visibility boundary |
| organizations:ListAccounts | denied | member account visibility boundary |

## Lessons / Gotchas

1. **Organizations apply multiple SCPs, not just one.** Different guardrails target different service families. The two known SCPs here (p-whl27g4i for IAM/security services, p-83yq4wr7 for Identity Center) demonstrate this.

2. **"AccessDenied" is not always SCP-driven.** The `create-permission-set` call returned an AccessDenied without an SCP ARN, indicating the identity policy check failed (likely because the target instance does not exist, making the request unresolvable). Always read the error message carefully.

3. **Member accounts cannot see SCPs.** `ListPolicies` is denied from a member account, by design. SCPs are visible only from the management account.

4. **Identity Center exists once per organization per region pair.** A member account cannot create an instance; that is a management account operation.

5. **Identity Center is the preferred pattern for humans in 2024+.** The exam and real-world practice both assume familiarity with permission sets, identity sources, and assignments.

6. **Read-only API probes reveal more than they seem to.** Distinguishing between "SCP block" and "resource does not exist" and "identity deny" is a critical skill for debugging access in enterprise AWS environments.

## Files

- `README.md` (this file)

No policy files were created for this lab because the operations were blocked at the org level.

## Real-World Application

In enterprise AWS, Identity Center is the standard way to give employees access:

- New hire onboards in Okta/Azure AD/Google Workspace
- Their group membership maps to permission sets in Identity Center
- They log into the SSO portal, pick a role, and get a session
- Offboarding is a single IdP deactivation, removing access to every account

This pattern eliminates the entire class of problems around long-lived IAM user credentials, provides a unified audit trail, and scales to hundreds of accounts without per-account IAM management.

The SCPs observed in this account are the guardrails that enterprises use to enforce policies like "no new Identity Center instances" or "no new IAM groups" across all member accounts. Understanding both the pattern and its guardrails is core to security architecture.