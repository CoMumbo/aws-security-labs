# Lab 3.2 - S3 Security - Bucket Policies, Block Public Access, ACLs vs Policies

**Date:** 2026-10-19
**Goal:** Understand the S3 security model by demonstrating the full breach lifecycle: prove that a public bucket policy is blocked by default, deliberately remove the safety net, make the bucket public, then restore the safety net and add encryption enforcement.

## Objective

1. Verify the baseline - bucket has no policy, no public access
2. Prove that Block Public Access prevents making a bucket public
3. Deliberately disable Block Public Access and expose the bucket
4. Prove anonymous access works (as an attacker would)
5. Restore Block Public Access, prove anonymous access is denied again
6. Enable account-level Block Public Access (the correct default)
7. Write an encryption-enforcement bucket policy
8. Prove unencrypted uploads are denied, encrypted uploads succeed

## Concept: The S3 Security Model

S3 access is controlled by multiple layers:

1. **IAM identity policies** - attached to users/roles
2. **Bucket policies** (resource-based) - attached to the bucket, use Principal element
3. **Bucket ACLs** (legacy) - legacy mechanism, being phased out
4. **Block Public Access** (account + bucket level) - safety net that overrides policies/ACLs

For an action to succeed, the effective allow must come from IAM OR the bucket policy (or both, depending on account ownership). Explicit Deny anywhere wins.

## Concept: The Four Block Public Access Flags

| Flag | What it blocks |
|---|---|
| `BlockPublicAcls` | Rejects any ACL that grants public access |
| `IgnorePublicAcls` | Ignores existing public ACLs (even if they were created before) |
| `BlockPublicPolicy` | Rejects bucket policies that allow public access |
| `RestrictPublicBuckets` | Restricts cross-account access that would be public |

**All four must be true for full protection.** AWS enabled all four at the bucket level by default for every bucket created after April 2023, in response to years of S3 data breaches.

**Account-level Block Public Access** is a separate control at the account scope. When enabled, it overrides everything at the account level, regardless of bucket-level settings.

Both levels can be independently configured. The safest posture: enabled at both.

## Concept: ACLs vs Policies

**ACLs (Access Control Lists)**:
- Legacy from S3's 2006 origins
- Attach permissions to a bucket or object using canonical user IDs or predefined groups (AllUsers, AuthenticatedUsers)
- The `AllUsers` group is what caused most early public-bucket breaches
- AWS now discourages ACLs entirely

**Bucket Policies**:
- Modern, JSON-based, resource-based policies
- Use standard IAM policy syntax (Principal, Action, Resource, Condition)
- Support conditions on request headers, IP ranges, VPC endpoints, MFA state
- This is the correct way to control S3 access

**Best practice:** disable ACLs entirely (Object Ownership = BucketOwnerEnforced). Then all access is controlled by bucket policies and IAM.

## What Was Built

| Resource | Value |
|---|---|
| Bucket name | lab32-s3-sec-803964124082-20261019123937 |
| Initial bucket PAB | All four flags true (AWS default) |
| Initial account PAB | None (not configured - this was a gap) |
| After lab: bucket PAB | All four flags true (restored) |
| After lab: account PAB | All four flags true (added - the fix) |
| Bucket policy (final) | Denies unencrypted s3:PutObject |
| Files in bucket | test-file.txt, good-upload.txt |

## Setup Commands

### 1. Check account-level Block Public Access

aws s3control get-public-access-block --account-id 803964124082

Initial result: NoSuchPublicAccessBlockConfiguration. Account-level protection was not configured.

### 2. Create a bucket

$bucketName = "lab32-s3-sec-803964124082-$(Get-Date -Format 'yyyyMMddHHmmss')"
aws s3 mb "s3://$bucketName"

### 3. Upload a test file

"This is test data for Lab 3.2" | Out-File -Encoding ascii test-file.txt
aws s3 cp test-file.txt "s3://$bucketName/test-file.txt"

### 4. Verify baseline - bucket is not public

$url = "https://$bucketName.s3.eu-north-1.amazonaws.com/test-file.txt"
Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop

Result: 403 Forbidden (anonymous access denied)

## The Breach Lifecycle Demonstration

### Attempt 1 - Try to make it public

$policy = '{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::' + $bucketName + '/*"}]}'
$policy | Out-File -Encoding ascii policies\public-read-policy.json
aws s3api put-bucket-policy --bucket $bucketName --policy file://policies/public-read-policy.json

Result: AccessDenied

Error message includes:
because public policies are prevented by the BlockPublicPolicy setting in S3 Block Public Access.

The default Block Public Access saved us from making a mistake.

### The Gap - Bucket-level Block Public Access Was On, but Account-Level Was Not

Verification:

aws s3api get-public-access-block --bucket $bucketName

Returned all four flags true for the bucket. The AWS default per-bucket protection is working. But the account-level setting was missing entirely - there was no account-wide safety net for buckets that might not have their own settings.

### Attempt 2 - Deliberately disable Block Public Access

aws s3api delete-public-access-block --bucket $bucketName

Result: Success (no output means success)

### Attempt 3 - Try to apply the public policy again

aws s3api put-bucket-policy --bucket $bucketName --policy file://policies/public-read-policy.json

Result: Success. The bucket is now public.

### Proof - Anonymous access works

$url = "https://$bucketName.s3.eu-north-1.amazonaws.com/test-file.txt"
try {
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
    Write-Host "SUCCESS - PUBLIC ACCESS WORKS: $($response.Content)"
} catch {
    Write-Host "Denied: $($_.Exception.Response.StatusCode.value__)"
}

Result:
SUCCESS - PUBLIC ACCESS WORKS: This is test data for Lab 3.2

No credentials. No signed request. Just a URL that any browser could open. This is what an S3 data breach looks like.

### Remediation Step 1 - Remove the public policy

aws s3api delete-bucket-policy --bucket $bucketName

### Remediation Step 2 - Re-enable Block Public Access on the bucket

aws s3api put-public-access-block --bucket $bucketName --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

### Remediation Step 3 - Verify anonymous access is denied again

$url = "https://$bucketName.s3.eu-north-1.amazonaws.com/test-file.txt"
Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop

Result: 403 Forbidden (correct)

### Remediation Step 4 - Enable Account-Level Block Public Access (the fix)

aws s3control put-public-access-block --account-id 803964124082 --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

Verification:

aws s3control get-public-access-block --account-id 803964124082

Returned: all four flags true. Account-level protection is now on. Every bucket in the account is protected by default, even if its own settings are misconfigured.

## Encryption-Enforcement Bucket Policy

File: policies/require-encryption-policy.json

$encPolicy = '{"Version":"2012-10-17","Statement":[{"Sid":"DenyUnencryptedUploads","Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::' + $bucketName + '/*","Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption":"AES256"}}}]}'
$encPolicy | Out-File -Encoding ascii policies\require-encryption-policy.json
aws s3api put-bucket-policy --bucket $bucketName --policy file://policies/require-encryption-policy.json

The policy denies any PutObject that does not include the header s3:x-amz-server-side-encryption: AES256.

### Test - Unencrypted upload is denied

aws s3 cp bad-upload.txt "s3://$bucketName/bad-upload.txt"

Result:
An error occurred (AccessDenied) when calling the PutObject operation: User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform: s3:PutObject on resource: "arn:aws:s3:::lab32-s3-sec-803964124082-20261019123937/bad-upload.txt" with an explicit deny in a resource-based policy

Note the phrase "explicit deny in a resource-based policy" - this is the audit signal for a bucket policy deny.

### Test - Encrypted upload succeeds

aws s3 cp bad-upload.txt "s3://$bucketName/good-upload.txt" --sse AES256

Result: upload succeeded.

### Verify - Only encrypted file exists

aws s3 ls "s3://$bucketName/"

Returned:
2026-10-19 12:54:05         23 good-upload.txt
2026-10-19 12:40:19         31 test-file.txt

No bad-upload.txt. The policy worked.

## Key Insights

### 1. The Default Is Now Safe

Every new bucket created after April 2023 has Block Public Access enabled by default. Trying to make it public without first disabling this protection fails. This is why modern S3 is much safer than pre-2023 S3.

### 2. Account-Level Protection Is Independent

Bucket-level Block Public Access can be overridden per bucket. Account-level Block Public Access overrides everything in the account. Both must be enabled for full protection. In this lab, the account was missing this protection entirely at the start.

### 3. Making a Bucket Public Takes Two Deliberate Steps

In the correct default configuration:
1. Disable Block Public Access (requires explicit delete-public-access-block)
2. Apply a public policy (requires explicit put-bucket-policy)

Both steps are logged in CloudTrail with the caller identity. This gives auditors the trail they need.

### 4. The Deny Is Explicit

The encryption policy uses explicit Deny, not just a missing Allow. The error message distinguishes:
- "explicit deny in a resource-based policy" - a policy says Deny
- "no identity-based policy allows" - IAM doesn't have an Allow

The first is a deliberate block. The second is default-deny.

### 5. Block Public Access Overrides Everything

Even if the bucket policy says Principal "*" Allow s3:GetObject, and even if the ACL grants AllUsers READ, if BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy are true, the bucket is not public. This is the safety net.

## Real-World Application

### The S3 Breach Problem

Before Block Public Access was introduced in 2018, S3 breaches were extremely common:

- 2017: Accenture - four S3 buckets publicly readable, exposing internal credentials
- 2017: Verizon - 14 million customer records exposed via an unsecured S3 bucket
- 2017: Dow Jones - 2.2 million customers exposed
- 2018: Exactis - 340 million records
- 2019: Capital One - 100 million customer records (not S3 public access, but IAM role misconfiguration)

The AWS response:
1. 2018: Introduced Block Public Access (opt-in)
2. 2023: Enabled by default on all new buckets
3. Continued: continued to add account-level and organization-level controls

Modern S3 misconfigurations are usually the result of deliberate action, not accidents. CloudTrail shows who did what.

### Best Practices from This Lab

1. **Enable account-level Block Public Access** as a baseline. This is the single most effective S3 security control.

2. **Leave bucket-level Block Public Access enabled** unless the bucket explicitly needs public access (static websites, public data sets).

3. **Use bucket policies with conditions** for fine-grained control (encryption enforcement, IP ranges, VPC endpoints, MFA).

4. **Disable ACLs entirely** (Object Ownership = BucketOwnerEnforced). All access via bucket policies.

5. **Enforce TLS only** with a bucket policy:

```json
{
  "Sid": "DenyInsecureTransport",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
  "Condition": { "Bool": { "aws:SecureTransport": "false" } }
}
Enforce encryption with the policy demonstrated above.

Log access - enable S3 access logging or CloudTrail data events.

Monitor - enable S3 findings in Security Hub, use Access Analyzer.

The Multi-Layer Defense
Block Public Access at account and bucket level

Bucket policies for encryption and TLS enforcement

IAM policies for user/role-level access

Access logging to CloudTrail or S3 server access logs

GuardDuty for S3 threat detection (when available)

Access Analyzer for unintended external access (when available)

No single layer catches everything. The combination prevents the common cases.

Lessons / Gotchas
Block Public Access is enabled by default on all new buckets (April 2023+). Attempting to make a bucket public without disabling it first will fail with "public policies are prevented by the BlockPublicPolicy setting".

Account-level and bucket-level Block Public Access are independent. Both must be enabled for full protection.

The API to enable is put-public-access-block; to disable is delete-public-access-block. Both are logged in CloudTrail.

ACLs are legacy. The AllUsers group is the historical cause of most public S3 data. Modern S3 uses bucket policies. Disable ACLs by setting Object Ownership = BucketOwnerEnforced.

Explicit Deny messages are distinguishable from default-deny. "explicit deny in a resource-based policy" means a policy says no. "no identity-based policy allows" means nothing grants the permission.

Encryption enforcement via bucket policy overrides IAM Allow. Even a principal with s3:* on the bucket cannot upload without the required encryption header.

S3 encryption at rest is enabled by default (SSE-S3) on all uploads. The encryption-enforcement policy is about audit evidence - proving encryption was requested, not just applied by default.

Block Public Access does not prevent cross-account access via specific account IDs - only via Principal "*". A bucket policy granting arn:aws:iam::ACCOUNT:root s3:GetObject still works, even with Block Public Access on.

Public access in the context of Block Public Access means "Principal: *" - a specific named AWS account is not considered public.

Access Analyzer (when not SCP-blocked) flags resources with unintended external access. In this account, that service is unavailable, so Block Public Access is the primary defense.

Files
policies/public-read-policy.json - the deliberate public-read policy (demonstration)

policies/require-encryption-policy.json - the encryption enforcement policy

bucket-pab.json - final bucket-level Block Public Access configuration

account-pab.json - final account-level Block Public Access configuration

bucket-policy.json - final bucket policy

test-file.txt - the uploaded test data

bad-upload.txt - used for the encryption enforcement test

Cleanup
aws s3 rm "s3://
b
u
c
k
e
t
N
a
m
e
"
−
−
r
e
c
u
r
s
i
v
e
a
w
s
s
3
r
b
"
s
3
:
/
/
bucketName"−−recursiveawss3rb"s3://bucketName"

Optional (do not do this if other workloads depend on it):
aws s3control delete-public-access-block --account-id 803964124082

Recommendation: leave account-level Block Public Access enabled permanently. It is a defense that catches mistakes.

Real-World Application
S3 is the most-used AWS service and historically the most-breached. The majority of incidents were caused by:

Making a bucket public for a one-time test, then forgetting to revert

ACLs with AllUsers READ

Bucket policies with Principal "*"

Compromised credentials uploading public data

Block Public Access at the account level makes it impossible for these mistakes to happen, without disabling the protection explicitly. Combined with CloudTrail logging, the protection becomes an audit trail: if someone makes a bucket public, there is a record.

The pattern in this lab (prove the breach, then fix) is the same pattern in real incident response: understand how the exposure happened, then verify the fix. The remediation here (enable account-level Block Public Access) is the correct permanent fix, not just cleaning up the specific bucket.
