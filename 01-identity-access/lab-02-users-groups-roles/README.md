# Lab 1.2 - Users, Groups, Roles

**Date:** 2026-10-08
**Goal:** Understand the three IAM identity types, design a full Users/Groups/Roles setup, and validate effective permissions. Adapted mid-lab after an organization-level Service Control Policy (SCP) blocked IAM write operations.

## Objective

1. Build an IAM Group with the S3 read-only policy attached
2. Add a User to the group and test inherited permissions
3. Create an IAM Role with a trust policy for EC2
4. Compare Users vs Groups vs Roles and understand when to use each

## The Blocker: Organization-Level SCP

During execution, aws iam create-group failed with:

User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to
perform: iam:CreateGroup on resource: arn:aws:iam::803964124082:group/S3-Analysts
with an explicit deny in a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

### What this means

- The account 803964124082 is a member account in AWS Organizations o-g4oan97ai8
- The management account is 321043732798
- An SCP with ID p-whl27g4i is attached with explicit Deny statements
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

### 2. The EC2 Trust Policy

File: policies/roles/ec2-trust-policy.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

This trust policy means: only the EC2 service may assume this role.

## Users vs Groups vs Roles

| Aspect | IAM User | IAM Group | IAM Role |
|---|---|---|---|
| What it is | A permanent identity | A container for users | A temporary identity |
| Has credentials? | Yes (password, access keys) | No | No permanent ones |
| Credential lifetime | Permanent until rotated | N/A | Minutes to hours (STS) |
| Can be leaked? | Yes, indefinitely | N/A | Yes, but expires |
| Used by | Humans | Humans (organized) | AWS services, cross-account, federation |
| Policies attached | Directly, via groups, via boundary | Directly | Trust policy + permission policies |
| Best practice in 2024+ | Avoid where possible | Organize users | Use for everything non-human |

Golden rule:

- Users are for humans who need long-term console access
- Groups organize users and simplify permission management
- Roles are for everything else: EC2, Lambda, cross-account, federated users

### Trust Policy vs Permission Policy

Every role has two policy types:

- Trust policy (assume role policy): Defines WHO can assume the role. One per role.
- Permission policy: Defines WHAT the role can do once assumed. Can be multiple.

Both must allow for an action to succeed:

1. The trust policy must allow the principal to call sts:AssumeRole
2. Once assumed, the permission policy must allow the target action

## Simulator Validation

### Test: iam:CreateGroup (should be explicitDeny via SCP)

Command:

aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::803964124082:user/admin-zeff" --action-names "iam:CreateGroup"

Result: explicitDeny. Matches the live API behaviour, showing the SCP effect is deterministic.

### Test: s3:ListAllMyBuckets (should be allowed)

Command:

aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::803964124082:user/admin-zeff" --action-names "s3:ListAllMyBuckets"

Result: allowed.

## What I Would Have Deployed (If Not SCP-Blocked)

# 1. Create the policy
aws iam create-policy --policy-name S3ReadOnlyAnalyst --policy-document file://policies/s3-readonly-analyst.json

# 2. Create the group and attach the policy
aws iam create-group --group-name S3-Analysts
aws iam attach-group-policy --group-name S3-Analysts --policy-arn "arn:aws:iam::ACCOUNT:policy/S3ReadOnlyAnalyst"

# 3. Create the user and add to the group
aws iam create-user --user-name analyst-user
aws iam add-user-to-group --user-name analyst-user --group-name S3-Analysts

# 4. Create the EC2 role
aws iam create-role --role-name EC2-S3-Read-Role --assume-role-policy-document file://policies/roles/ec2-trust-policy.json
aws iam attach-role-policy --role-name EC2-S3-Read-Role --policy-arn "arn:aws:iam::ACCOUNT:policy/S3ReadOnlyAnalyst"

## Lessons / Gotchas

1. SCPs are invisible to member accounts. A member account cannot list, view, or modify SCPs attached to it, even with AdministratorAccess.
2. SCPs evaluate before identity policies. An explicit Deny in an SCP beats every Allow anywhere else.
3. The OrganizationsDecisionDetail field in simulator output is the tell for SCP-driven denies.
4. Read-only plus simulation is a valid learning mode. In enterprise environments, engineers often work in accounts they cannot modify.
5. Trust policies are the who; permission policies are the what. Confusing the two is a common source of role misconfigurations.
6. Groups reduce permission sprawl. Attaching a policy to a group is cleaner than attaching it to each user directly.

## Cleanup

aws iam delete-policy --policy-arn "arn:aws:iam::803964124082:policy/S3ReadOnlyAnalyst"
aws s3 rb s3://scp-test-bucket-803964124082

Verified with:

aws iam list-policies --scope Local   # empty
aws s3 ls                             # empty

## Files

- policies/s3-readonly-analyst.json - the S3 read policy
- policies/roles/ec2-trust-policy.json - the EC2 trust policy
- screenshots/ - terminal evidence of the SCP block

## Real-World Application

In enterprise AWS environments, engineers frequently encounter SCPs that block specific actions. The right response is:

1. Reproduce the error precisely (the error message names the SCP ARN)
2. Identify the SCP owner (management account + org admins)
3. Request an exception with business justification
4. Or adapt the design to work within the guardrail

Knowing how to trace an access denial through the AWS policy evaluation chain (identity policy, permission boundary, SCP, resource policy) is a core IAM skill.
