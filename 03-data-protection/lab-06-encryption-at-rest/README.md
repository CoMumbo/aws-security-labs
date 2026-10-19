# Lab 3.6 - Encryption at Rest - EBS, RDS, S3

**Date:** 2026-10-19
**Goal:** Understand how AWS encrypts data at rest across the primary storage services. Enable EBS default encryption as a permanent security improvement, verify S3 encryption at both bucket and object level, and map the AWS-managed KMS keys behind each service.

## Objective

1. Survey the encryption state of EBS, RDS, and S3
2. Enable EBS default encryption (account-wide security win)
3. Create an S3 bucket and inspect its default encryption
4. Upgrade the bucket to KMS encryption with bucket keys
5. Upload an object and verify KMS encryption at the object level
6. Observe AWS-managed KMS keys being lazily created on first use
7. Identify the CloudTrail gap

## Concept: Encryption at Rest Across AWS

AWS services handle encryption at rest in three ways:

### 1. Encrypted by Default (no opt-in)

- **S3** - all new buckets are encrypted with SSE-S3 since January 2023
- **EBS** - can be set as default per region with `enable-ebs-encryption-by-default`
- **RDS** - StorageEncrypted flag is set at instance creation
- **EFS** - encrypted at rest by default
- **DynamoDB** - always encrypted with AWS-managed keys

### 2. Optional (set at creation)

- **EBS** - per-volume, unless default encryption is on
- **RDS** - per-instance, cannot be changed after creation
- **EFS** - can be enabled at creation only
- **ElastiCache** - optional
- **Redshift** - optional

### 3. Encryption Keys

Three key types are possible:

- **AWS-owned keys** - completely managed by AWS, not visible in your account (used by DynamoDB, S3 Glacier default, etc.)
- **AWS-managed keys** - visible in your account as `alias/aws/<service>`, free, rotated annually by AWS
- **Customer-managed keys (CMKs)** - created and managed by you, $1/month, custom rotation and policy

The distinction matters for compliance: only CMKs allow control over the key policy, rotation schedule, and cross-account sharing.

## What Was Built

| Resource | Status |
|---|---|
| EBS default encryption | Enabled (was false) |
| S3 bucket | lab36-enc-test-803964124082-20261019145914 |
| Initial S3 encryption | SSE-S3 (AES256), SSE-C blocked |
| Final S3 encryption | SSE-KMS (aws:kms), bucket key enabled, SSE-C blocked |
| Test object | enc-test.txt |
| Object encryption | aws:kms with aws/s3 key (27aef5f7-8019-420d-bc10-a16a3910b048) |
| EBS KMS key | 7cc59af0-fcc4-42a3-8b43-345a26ae68da (alias/aws/ebs) |
| RDS KMS key | 5806154b-9f28-446d-8510-f25f2d8593d3 (alias/aws/rds) |
| Secrets Manager KMS key | 953a4668-7808-4ce5-a0d7-55d5f1196802 (alias/aws/secretsmanager) |
| SSM KMS key | d7927011-3bc0-4e6c-a9aa-69646f9d6f70 (alias/aws/ssm) |
| CloudTrail trail | None - gap identified |

## Initial Survey

### EBS default encryption

aws ec2 get-ebs-encryption-by-default

Returned: EbsEncryptionByDefault: false

This is a common finding. Without default encryption, every new EBS volume is created unencrypted unless the caller explicitly requests encryption. Enabling this is a one-line security win.

### Existing volumes

aws ec2 describe-volumes

Returned: empty (no volumes in the account)

### RDS instances

aws rds describe-db-instances

Returned: empty (no databases)

### S3 bucket encryption

aws s3api get-bucket-encryption --bucket nonexistent

Returned: Connection error (bucket name invalid format)

## Enabling EBS Default Encryption

aws ec2 enable-ebs-encryption-by-default

Returned: { "EbsEncryptionByDefault": true }

Verification:

aws ec2 get-ebs-encryption-by-default

Returned: { "EbsEncryptionByDefault": true }

### What this does

- Every new EBS volume in eu-north-1 is encrypted automatically
- Every new EBS snapshot is encrypted
- Every snapshot copy is encrypted
- Existing unencrypted volumes are NOT retroactively encrypted (requires snapshot-copy workflow)
- Uses the AWS-managed alias/aws/ebs KMS key by default

### What this means for compliance

Most security frameworks (CIS, PCI, HIPAA, SOC 2) require encryption at rest. Auditing tools check `EbsEncryptionByDefault` in each region. Setting it to true removes the finding for new volumes. For existing volumes, the snapshot-copy-encrypt process handles migration.

### Per-region scope

EBS default encryption is per-region. Enabling in eu-north-1 does not affect us-east-1. Best practice: enable in every region the account uses.

## S3 Default Encryption (2023+)

### Create a bucket

$bucketName = "lab36-enc-test-803964124082-$(Get-Date -Format 'yyyyMMddHHmmss')"
aws s3api create-bucket --bucket $bucketName --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1

### Inspect default encryption

aws s3api get-bucket-encryption --bucket $bucketName

Returned:

```json
{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                },
                "BucketKeyEnabled": false,
                "BlockedEncryptionTypes": {
                    "EncryptionType": ["SSE-C"]
                }
            }
        ]
    }
}
What this tells us
SSEAlgorithm: AES256 - SSE-S3, AWS-managed key per object, no KMS involvement

BucketKeyEnabled: false - not relevant for SSE-S3 (only for SSE-KMS)

BlockedEncryptionTypes: SSE-C - uploads with customer-provided keys are blocked

SSE-S3 provides encryption at rest without any configuration. Since January 2023, this is the default for every new bucket. No more unencrypted S3 buckets.

SSE-C blocking is a 2023+ default. Customers who upload with their own encryption keys (SSE-C) bypass AWS key management entirely. Blocking this is a governance decision - the account decides keys must be managed by AWS or the customer via KMS, not by whatever key the uploader chooses.

Upgrading to KMS Encryption
Change the bucket encryption
aws s3api put-bucket-encryption --bucket $bucketName --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}'

Verify
aws s3api get-bucket-encryption --bucket $bucketName

Returned:

json
{
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms"
                },
                "BucketKeyEnabled": true,
                "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}
            }
        ]
    }
}
What changed
AES256 -> aws:kms - objects now use KMS-managed keys, CloudTrail logs every decrypt

BucketKeyEnabled false -> true - S3 generates a bucket-level data key encrypted by KMS, reducing KMS calls by up to 99%

Why BucketKeyEnabled matters
Without bucket keys, every S3 PUT and GET makes a KMS call. At $0.03 per 10,000 requests, a high-volume bucket can generate enormous KMS costs. With bucket keys, S3 reduces KMS calls dramatically - one data key per bucket, refreshed every 24 hours, used for all objects.

AWS recommends bucket keys for any bucket above a low threshold of access volume. The default in the console is now enabled; via API, you must set it explicitly.

Object-Level Encryption
Upload an object
aws s3 cp enc-test.txt "s3://$bucketName/enc-test.txt"

Verify object encryption
aws s3api head-object --bucket $bucketName --key enc-test.txt

Returned:

json
{
    "ServerSideEncryption": "aws:kms",
    "SSEKMSKeyId": "arn:aws:kms:eu-north-1:803964124082:key/27aef5f7-8019-420d-bc10-a16a3910b048",
    "BucketKeyEnabled": true
}
The object is encrypted with the AWS-managed aws/s3 key.

AWS-Managed Keys Are Lazily Created
Before upload
aws kms list-aliases --query "Aliases[?AliasName=='alias/aws/s3']"

Returned: alias/aws/s3 with KeyId: None

After upload
aws kms list-aliases --query "Aliases[?AliasName=='alias/aws/s3']"

Returned: alias/aws/s3 with KeyId: 27aef5f7-8019-420d-bc10-a16a3910b048

Why this matters
AWS-managed KMS keys do not exist until the first service needs them. The alias exists (visible in list-aliases), but the underlying key is created on first use.

Operational implication: If you delete all objects from a bucket and later check the KMS key, it still exists. But if you check the alias before any object existed, there was no key. The alias -> key mapping is lazy.

The CloudTrail Gap
Check for trails
aws cloudtrail describe-trails

Returned: empty (no trails configured)

What this means
KMS Decrypt and Encrypt events are still recorded in the 90-day Event History (visible in the console, not via API)

No persistent trail means KMS audit logs are lost after 90 days

For compliance (PCI, HIPAA, SOC 2, SEC 17a-4), long-term retention is required

Security investigation of a KMS event older than 90 days is impossible

The fix (not done in this lab due to setup cost)
Create an S3 bucket for logs (with Object Lock for immutability)

Create a CloudTrail trail with the bucket as destination

Enable KMS event logging (Data Events for S3 optional but recommended)

Configure log file validation and encryption (SSE-KMS)

Monitor via CloudWatch Logs Insights or EventBridge

This is the standard pattern for enterprise CloudTrail. The absence of a trail in this account is a documented gap, not a design choice.

The Encryption Matrix
Service    Default    Configurable at    Key type default    CMK possible
EBS (new volumes)    Off until enabled    Region (default), volume    AWS-managed aws/ebs    Yes
EBS (snapshots)    Follows volume    Snapshot creation    AWS-managed aws/ebs    Yes
RDS    Off unless requested    Instance creation (immutable)    AWS-managed aws/rds    Yes
RDS (snapshots)    Follows instance    Snapshot creation    AWS-managed aws/rds    Yes
S3    On (SSE-S3)    Bucket, per-object override    SSE-S3 (AWS-managed)    Yes (SSE-KMS)
EFS    On    Filesystem creation (immutable)    AWS-managed aws/elasticfilesystem    Yes
DynamoDB    Always on    Table creation    AWS-owned    No (always AWS-owned)
Secrets Manager    Always on    Secret creation    AWS-managed aws/secretsmanager    Yes
SSM Parameter Store (SecureString)    Depends on type    Parameter creation    AWS-managed aws/ssm    Yes
Lessons / Gotchas
EBS default encryption is per-region. Enable in every region used. There is no single account-wide toggle.

EBS default encryption does not retroactively encrypt existing volumes. Migration requires creating an encrypted snapshot and creating a new volume from it.

S3 encryption cannot be disabled on new buckets. If you try to remove encryption, the API returns an error. This is by design post-2023.

S3 SSE-S3 vs SSE-KMS is a real operational difference. SSE-S3 is free and has no per-object KMS calls. SSE-KMS costs $0.03 per 10,000 API calls and provides per-object audit trail. For most workloads, SSE-S3 is sufficient. For compliance-audit workloads, SSE-KMS is required.

BucketKeyEnabled only matters for SSE-KMS. For SSE-S3, it is irrelevant. The console shows it disabled for SSE-S3 buckets.

RDS encryption is immutable at instance creation. There is no way to enable encryption on a running RDS instance. Migration requires: snapshot -> encrypted snapshot copy -> new instance from encrypted snapshot. This takes a maintenance window.

AWS-managed KMS keys are lazily created. The alias is visible but the key does not exist until first use. This can be confusing in CloudTrail investigations - the key appears without warning.

KMS key rotation for AWS-managed keys is transparent (annual). For CMKs, you control the rotation schedule.

CloudTrail is mandatory for compliance. Without a trail, KMS events are only in the 90-day Event History. For any production account handling regulated data, this is a gap that must be closed.

S3 BlockedEncryptionTypes is a 2023+ feature. Blocking SSE-C is the default. If you have a legitimate use case for customer-provided keys, you must explicitly allow SSE-C in the bucket encryption config.

Files
ebs-default.json - EBS encryption by default status

bucket-encryption.json - S3 bucket encryption configuration

object-encryption.json - the uploaded object encryption details

aws-managed-keys.json - all AWS-managed KMS key aliases

Cleanup
The bucket must be emptied before it can be deleted.

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
a
p
i
d
e
l
e
t
e
−
b
u
c
k
e
t
−
−
b
u
c
k
e
t
bucketName"−−recursiveawss3apidelete−bucket−−bucketbucketName

The EBS default encryption setting is intentionally left ON - it is a permanent security improvement and should not be disabled.

The AWS-managed KMS keys (alias/aws/s3, alias/aws/ebs, etc.) are not deleteable. They persist as long as a resource references them.

Real-World Application
The Three-Tier Encryption Model
For any regulated workload, best practice is:

Tier 1 - Block storage (EBS)

Enable default encryption in every region

Use CMKs for workloads with compliance requirements

Audit via AWS Config rule encrypted-volumes

Tier 2 - Object storage (S3)

Default SSE-S3 for general workloads

SSE-KMS with bucket keys for compliance

Block public access at account level (from Lab 3.2)

Object Lock for immutable backups

Tier 3 - Database (RDS/Aurora)

Always enable StorageEncrypted at instance creation

Use CMKs for cross-account backup sharing

Automated backups inherit the encryption state

The Cross-Account Encrypted Backup Pattern
When backing up an encrypted RDS database to another account, the KMS key must be shared. The pattern:

Source account creates a CMK

Source account grants the destination account's KMS permission via key policy

Source account creates a backup and grants the destination account access

Destination account copies the backup using its own KMS key (re-encrypted)

Destination account's backup is encrypted with its own key, independent of the source

Without shared CMKs, cross-account encrypted backups fail because the destination account cannot decrypt the source's AWS-managed key.

The Compliance Audit Trail
For PCI, HIPAA, and SOC 2 compliance:

Every S3 object decrypt is logged in CloudTrail (when using SSE-KMS)

Every RDS backup is logged in CloudTrail

Every EBS volume creation is logged in CloudTrail

AWS Config rules verify encryption state continuously

The combination of CloudTrail (audit) + Config (compliance) + KMS (enforcement) is the standard enterprise pattern.

The Cost Model
EBS encryption: free (only the underlying storage cost)

RDS encryption: free (StorageEncrypted flag is free; KMS API calls are minimal)

S3 SSE-S3: free (no extra cost)

S3 SSE-KMS: $0.03 per 10,000 KMS API calls - use bucket keys to reduce

AWS-managed KMS keys: free

CMK: $1/month per key

For most workloads, encryption is effectively free. The operational cost is in the governance: audit reviews, key rotation tracking, policy management.

The Bottom Line
EBS: enable default encryption - one command, permanent benefit

S3: encrypted by default since 2023 - verify, don't assume

RDS: encrypted at creation - plan ahead, cannot change later

All three use KMS - understand which key type and why

CloudTrail is mandatory for audit - no exception for regulated data

Compliance frameworks require all three plus CloudTrail plus Config

Encryption at rest is a solved problem in AWS. The remaining work is operational: ensuring it is enabled everywhere, monitoring for changes, and having the audit trail that proves it was enabled the whole time.
