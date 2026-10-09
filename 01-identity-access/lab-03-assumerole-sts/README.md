# Lab 1.3 - AssumeRole and STS

**Date:** 2026-10-08
**Goal:** Understand role assumption, temporary credentials, and the Security Token Service (STS). Build a real role and assume it via the CLI to obtain temporary credentials.

## Objective

1. Design a trust policy that allows a specific IAM user to assume a role
2. Design a permission policy for the role (S3 read-only)
3. Create the role and attach the permission policy
4. Assume the role using aws sts assume-role
5. Prove identity changed and that least privilege applies

## Concept: How AssumeRole Works

Every role has two policy types:

- Trust policy (assume role policy): Defines who may assume the role
- Permission policy: Defines what the role can do once assumed

For a role to be assumed by a caller, BOTH must be true:

1. The role's trust policy allows the caller to call sts:AssumeRole
2. The caller's own identity policy allows sts:AssumeRole on the target role

If either side denies, the call fails.

## Design Artifacts

### Trust Policy

File: policies/analyst-trust-policy.json

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

Meaning: only the user admin-zeff in account 803964124082 may assume this role.

### Permission Policy

File: policies/analyst-permissions.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadAnyBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}

Meaning: once assumed, the role can read any S3 bucket but nothing else.

## Setup Commands

### 1. Create the role

aws iam create-role --role-name Analyst-Assumable-Role --assume-role-policy-document file://policies/analyst-trust-policy.json --description "Role assumable by admin-zeff for S3 read-only access"

### 2. Create the permission policy

aws iam create-policy --policy-name Analyst-Read-Any-Bucket --policy-document file://policies/analyst-permissions.json --description "Read access to any S3 bucket for the analyst role"

### 3. Attach the policy to the role

aws iam attach-role-policy --role-name Analyst-Assumable-Role --policy-arn "arn:aws:iam::803964124082:policy/Analyst-Read-Any-Bucket"

### 4. Simulate the caller's permission to assume

aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::803964124082:user/admin-zeff" --action-names "sts:AssumeRole" --resource-arns "arn:aws:iam::803964124082:role/Analyst-Assumable-Role"

Result: allowed (matched statement from AdministratorAccess). SCP does not block sts:AssumeRole.

### 5. Assume the role for real

aws sts assume-role --role-arn "arn:aws:iam::803964124082:role/Analyst-Assumable-Role" --role-session-name "zeph-test-session"

Output includes:

- Credentials.AccessKeyId starting with ASIA (temporary) - not AKIA (long-lived)
- Credentials.SessionToken - a large string required on every API call
- Credentials.Expiration - one hour from issue time
- AssumedRoleUser.Arn containing assumed-role/ and the session name

### 6. Use the credentials in the current shell

$env:AWS_ACCESS_KEY_ID="ASIA..."
$env:AWS_SECRET_ACCESS_KEY="..."
$env:AWS_SESSION_TOKEN="..."

## Validation

### Identity confirmed as the role

aws sts get-caller-identity

Output:

UserId:  AROA3WL767OZGYRFHSAWD:zeph-test-session
Account: 803964124082
Arn:     arn:aws:sts::803964124082:assumed-role/Analyst-Assumable-Role/zeph-test-session

Note the change from iam prefix to sts prefix, and the assumed-role/ path segment.

### Least privilege proven

The role has S3 read permissions only. Testing two actions from the same shell:

- aws s3 ls - succeeded (role has s3:ListAllMyBuckets)
- aws iam list-users - AccessDenied (role has no IAM permissions)

Same terminal session, different identity, different effective permissions. This is the least-privilege model in action.

### Cleanup

Returning to the original identity:

Remove-Item Env:\AWS_ACCESS_KEY_ID
Remove-Item Env:\AWS_SECRET_ACCESS_KEY
Remove-Item Env:\AWS_SESSION_TOKEN

Verify with aws sts get-caller-identity - ARN changes back to arn:aws:iam::803964124082:user/admin-zeff.

## Long-Lived vs Temporary Credentials

| Aspect | Long-Lived (IAM user) | Temporary (STS) |
|---|---|---|
| Prefix | AKIA | ASIA |
| Session token required | No | Yes |
| Expiration | None (until rotated) | Minutes to hours |
| Rotation | Manual | Automatic |
| Leak blast radius | Unlimited time | Limited to session duration |
| Best practice | Avoid for humans | Preferred for services and cross-account |

## Lessons / Gotchas

1. Trust policy AND identity policy must both allow. A common mistake is adding a trust policy for the caller but forgetting that the caller also needs sts:AssumeRole in their own permissions.
2. Temporary credentials need three values, not two. AccessKeyId, SecretAccessKey, and SessionToken. Forgetting the SessionToken causes SignatureDoesNotMatch errors.
3. Temporary credentials can be leaked too. They expire quickly, which limits the blast radius, but they are still secrets and should never be pasted into chats, logs, or repos.
4. The ARN prefix tells you what you are. arn:aws:iam:: means a static identity. arn:aws:sts:: with assumed-role/ means a temporary session.
5. Session name matters for auditing. Every action taken while assumed is logged in CloudTrail with the session name (zeph-test-session), making it possible to trace exactly which session made a given API call.
6. Least privilege is proven by what fails, not just what succeeds. The AccessDenied on iam:list-users was as important as the successful s3 ls.

## Files

- policies/analyst-trust-policy.json - the role trust policy
- policies/analyst-permissions.json - the role permission policy
- screenshots/02-assumed-role-identity.png
- screenshots/03-role-least-privilege-deny.png

## Real-World Application

AssumeRole is the foundation of modern AWS access:

- EC2 instances assume an instance profile role to call S3, DynamoDB, etc. with no keys on disk
- Lambda functions assume an execution role on every invocation
- Cross-account access works by Account A calling sts:AssumeRole on a role in Account B
- SSO / federation issues a role session after the identity provider authenticates the user
- CI/CD pipelines assume roles in deployment accounts, with short-lived credentials

Understanding the trust policy vs permission policy distinction, and knowing how to prove an assumed session via get-caller-identity, are core IAM skills tested on the SCS-C02 exam.
