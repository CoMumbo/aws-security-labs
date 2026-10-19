# Lab 3.1 - AWS KMS - CMKs, Envelope Encryption, Key Policies

**Date:** 2026-10-19
**Goal:** Build a customer-managed KMS key, understand key policies, and implement full envelope encryption from scratch in PowerShell. Prove the roundtrip: generate a data key, encrypt data with it, destroy it, recover it via KMS, decrypt the data.

## Objective

1. Create a customer-managed KMS key with a restricted key policy
2. Encrypt and decrypt data directly with KMS (small data only)
3. Generate a data key (plaintext + KMS-encrypted versions)
4. Encrypt bulk data with the plaintext data key
5. Destroy the plaintext data key
6. Recover it via KMS decrypt on the encrypted version
7. Decrypt the bulk data with the recovered key
8. Create and revoke a grant
9. Create an alias for the key

## Concept: What KMS Is

AWS Key Management Service is a managed encryption service. It stores keys, controls who can use them, and provides FIPS 140-2 validated HSMs under the hood. It never exposes raw key material to users.

There are two key types:

- **AWS-managed keys** (KeyManager = AWS)
  - Created and rotated by AWS automatically
  - Named like `aws/s3`, `aws/ebs`, `aws/rds`
  - Free, but not directly controllable
  - Cannot be deleted, cannot be shared cross-account
  - Rotation every year (configurable by AWS, not by you)

- **Customer-managed keys** (KeyManager = CUSTOMER)
  - Created by you, controlled by you
  - Custom key policy
  - Can be rotated (annual, on-demand)
  - Can be shared cross-account via key policy
  - $1/month per key + API call costs

This lab used a customer-managed key.

## Concept: Key Policies

A key policy is the **root of trust** for a KMS key. Unlike S3 bucket policies (which can allow anything), a KMS key policy is the *only* mechanism that can allow other policies to take effect.

The special behavior: if a principal isn't mentioned in the key policy, **no other policy** can grant them access. The key policy must explicitly allow the account (root) or a specific principal, and then IAM policies can further narrow access.

Every key policy must have at least one statement that grants `kms:*` (or equivalent) to a principal. If this statement is removed, the key becomes unmanageable - nobody can administer it.

Typical structure:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccountAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
The root statement alone allows any IAM principal in the account to access the key if their identity policy also allows it. This is the "delegation to IAM" pattern.

Alternative (more restrictive): list specific principals instead of root.

Concept: Envelope Encryption
KMS has a 4 KB plaintext limit per Encrypt call. For larger data, this is the pattern:

text
1. KMS generate-data-key  ->  plaintext data key (32 bytes)
                              + encrypted data key (KMS-encrypted)

2. Use the plaintext data key with AES-256 to encrypt bulk data
   (in-memory, SDK-managed, or manual)

3. Discard the plaintext data key

4. Persist the encrypted data key + encrypted data + IV/nonce

5. To decrypt:
   - Send the encrypted data key to KMS -> get plaintext data key
   - Decrypt the data with the recovered key
The tiny encrypted data key is what persists. The plaintext key is ephemeral. All traffic between your application and KMS is the small data key blob - never the bulk data.

This is how S3, EBS, RDS, EFS, S3 Glacier, DynamoDB, and every AWS encrypted service operates internally. AWS SDKs implement this pattern automatically.

What Was Built
Resource    ID
Customer-managed KMS key    arn:aws:kms:eu-north-1:803964124082:key/cfa447a7-7122-4c36-a619-e41fbe3b8ba3
Key alias    alias/lab31-demo-key
Key policy    2 statements: root account + admin-zeff user
Grant    Created and revoked (87f54b7606b2a3fd9b453db5b87b6b58dc073db9bae3e4d93f64f1dbc77662d4)
Original plaintext    "This is my secret data for Lab 3.1." (37 bytes)
Ciphertext from direct KMS encrypt    518-byte base64 blob
Data key plaintext    32 bytes (AES-256)
Data key ciphertext    AQIDAHhlWc0w... (base64 KMS blob)
Bulk data ciphertext    48 bytes (AES-256 of 37-byte plaintext, padded)
IV    yZQih2k2F6eBrpz/uzIHeA==
Setup Commands
1. Create the key policy
File: policies/lab31-key-policy.json

json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootAccountAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::803964124082:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAdminZeffFullAccess",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::803964124082:user/admin-zeff"},
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
2. Create the key
aws kms create-key --policy file://policies/lab31-key-policy.json --description "Lab 3.1 customer-managed key"

Returned KeyId: cfa447a7-7122-4c36-a619-e41fbe3b8ba3
Manager: CUSTOMER

3. Direct encrypt and decrypt (small data)
aws kms encrypt --key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3 --plaintext fileb://secret.txt --query CiphertextBlob --output text > encrypted.b64

The output is base64 ciphertext. To decrypt:

powershell
$b64 = (Get-Content encrypted.b64 -Raw).Trim()
$bytes = [System.Convert]::FromBase64String($b64)
[System.IO.File]::WriteAllBytes("$PWD\ciphertext.bin", $bytes)
aws kms decrypt --ciphertext-blob fileb://ciphertext.bin --query Plaintext --output text
Returned: VGhpcyBpcyBteSBzZWNyZXQgZGF0YSBmb3IgTGFiIDMuMS4NCg==
Which decodes to the original plaintext.

4. Generate a data key
aws kms generate-data-key --key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3 --key-spec AES_256

Returned:

json
{
  "Plaintext": "EfB07r4zZPVnZqqrev0DlLLrd9eu/R59w/PCraJJaQ0=",
  "CiphertextBlob": "AQIDAHhlWc0w... (long base64)"
}
The Plaintext field is the raw AES-256 key (base64-encoded). The CiphertextBlob is the same key encrypted by KMS.

5. Encrypt bulk data with the data key
In PowerShell:

powershell
$plaintext = [System.IO.File]::ReadAllBytes("$PWD\secret.txt")
$keyBytes = [System.IO.File]::ReadAllBytes("$PWD\datakey.bin")
$aes = New-Object System.Security.Cryptography.AesManaged
$aes.Key = $keyBytes
$aes.GenerateIV()
$iv = $aes.IV
$encryptor = $aes.CreateEncryptor()
$encrypted = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
[System.IO.File]::WriteAllBytes("$PWD\data-encrypted.bin", $encrypted)
[System.IO.File]::WriteAllBytes("$PWD\data-iv.bin", $iv)
Result: 37-byte plaintext becomes 48-byte ciphertext (AES-256 with PKCS7 padding).

6. Destroy the plaintext data key
powershell
Remove-Item datakey.bin -Force
Remove-Item datakey.json -Force
After this, the plaintext data key exists nowhere on disk. Only the KMS-encrypted version (saved separately) can recover it.

7. Recover the data key via KMS
powershell
$b64 = (Get-Content encrypted-datakey.b64 -Raw).Trim()
$bytes = [System.Convert]::FromBase64String($b64)
[System.IO.File]::WriteAllBytes("$PWD\encrypted-datakey.bin", $bytes)
$recovered = aws kms decrypt --ciphertext-blob fileb://encrypted-datakey.bin --query Plaintext --output text
$recoveredKeyBytes = [System.Convert]::FromBase64String($recovered)
[System.IO.File]::WriteAllBytes("$PWD\recovered-datakey.bin", $recoveredKeyBytes)
Result: 32 bytes recovered. The data key is back in plaintext form.

8. Decrypt the bulk data
powershell
$ciphertext = [System.IO.File]::ReadAllBytes("$PWD\data-encrypted.bin")
$key = [System.IO.File]::ReadAllBytes("$PWD\recovered-datakey.bin")
$iv = [System.IO.File]::ReadAllBytes("$PWD\data-iv.bin")
$aes = New-Object System.Security.Cryptography.AesManaged
$aes.Key = $key
$aes.IV = $iv
$decryptor = $aes.CreateDecryptor()
$decrypted = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
$plaintext = [System.Text.Encoding]::UTF8.GetString($decrypted)
Write-Host "Decrypted: $plaintext"
Result: "Decrypted: This is my secret data for Lab 3.1."

Full roundtrip proven.

9. Create a grant (temporary access delegation)
aws kms create-grant --key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3 --grantee-principal "arn:aws:iam::803964124082:user/admin-zeff" --operations Decrypt DescribeKey --name "lab31-grant"

Returned:

GrantToken: AQpAMzc0YzBmZTVi... (KMS-generated base64)

GrantId: 87f54b7606b2a3fd9b453db5b87b6b58dc073db9bae3e4d93f64f1dbc77662d4

10. Revoke the grant
aws kms revoke-grant --key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3 --grant-id 87f54b7606b2a3fd9b453db5b87b6b58dc073db9bae3e4d93f64f1dbc77662d4

After revoke, the grantee can no longer use the key for those operations - unless they also have key policy permission.

11. Create an alias
aws kms create-alias --alias-name alias/lab31-demo-key --target-key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3

Aliases resolve to the underlying KeyId. Applications reference the alias so that key rotation is a matter of repointing the alias - no code change.

Key Policies vs Grants
Both mechanisms grant access to a KMS key, but in different ways:

Aspect    Key Policy    Grant
Type    JSON document    Programmatic object
Persistence    Attached to key    Attached to key
Visibility    Always listed    Listed only with kms:ListGrants
Modification    put-key-policy    create-grant / revoke-grant
Size limit    32 KB    Limited count
Best for    Baseline access    Temporary delegation
Cross-account    Yes    Yes (with constraints)
Services use it?    No (always use grants)    Yes (AWS services create grants)
Critical insight: AWS services (S3, EBS, RDS, CloudWatch, etc.) create grants when they use a customer-managed key on your behalf. These grants are how the service principal gets permission without being in the key policy.

Common gotcha: If a KMS key policy is modified and removes a service's implicit grant, the service may lose access. AWS-managed grants are recreated automatically in most cases, but explicit grants you've created are not.

Real-World Application
What KMS Encrypts For You
AWS services use KMS for encryption-at-rest automatically:

S3 server-side encryption (SSE-KMS)

EBS volume encryption

RDS database encryption

EFS file system encryption

S3 Glacier, DynamoDB, ElastiCache

Lambda environment variables

CloudWatch Logs

SQS, SNS messages (optional)

Secrets Manager secrets

In all cases, the service generates a data key per object/volume/message, uses envelope encryption internally, and stores only the KMS-encrypted data key.

Multi-Region Keys
For latency and disaster recovery, KMS supports multi-region keys - replicas of the same key in multiple regions. The key ID and key material are identical across regions, so encrypted data can be decrypted in any region without re-encryption.

Cost: one primary + replicas per region (~$1/month each).

Cross-Account KMS
KMS keys can be shared with other AWS accounts via key policy. The typical pattern:

Key owner adds arn:aws:iam::OTHER-ACCOUNT:root to the key policy

Other account's admin delegates to their principals via IAM

Encrypted data can be shared securely (data is useless without KMS decrypt permission)

This is the mechanism behind cross-account encrypted S3 replication, centralized log storage, and shared encrypted snapshots.

Key Rotation
Customer-managed keys support two rotation modes:

Automatic (recommended) - KMS rotates the backing key annually

Manual - create a new key, update the alias, re-encrypt or use re-encryption jobs

Automatic rotation is transparent: the KeyId stays the same, only the backing key material changes. Old data remains decryptable.

Cost Model
AWS-managed keys: Free

Customer-managed keys: $1/month per key

API calls: $0.03 per 10,000 requests (Encrypt, Decrypt, GenerateDataKey)

Grants: Free

Aliases: Free

For workloads doing high-volume encryption, cost is dominated by API calls. Caching data keys client-side (using the AWS Encryption SDK) can dramatically reduce cost.

When NOT to Use KMS
Large volumes of data - use S3 SSE-KMS or client-side envelope encryption, not per-file KMS Encrypt calls

Frequently-changing keys - if you need rotation every hour, KMS isn't the tool; use a secrets manager

External key material requirements - use CloudHSM instead (dedicated HSM, higher cost)

On-premises only - KMS requires AWS APIs; use a local HSM

Lessons / Gotchas
fileb:// vs file:// - AWS CLI has two file prefixes. file:// reads as text (UTF-8). fileb:// reads as binary. Ciphertext must use fileb://.

--output text adds newlines - when you save the CiphertextBlob from --query + --output text, PowerShell may add line breaks. Always trim with .Trim() before decoding.

KMS 4 KB limit - direct Encrypt calls are limited to 4 KB. For larger data, use generate-data-key + envelope encryption.

Key policy is the root of trust - no other policy can grant access if the key policy doesn't allow the principal. Removing the root account statement locks the key forever.

Aliases are not the key - alias/name resolves to the KeyId at call time. Rotating the alias is how you rotate keys without changing application code.

Grants are temporary delegation - grants let specific principals do specific operations on the key, without being in the key policy. They expire, are revocable, and AWS services use them constantly.

KMS is not a secret store - use Secrets Manager or Parameter Store for passwords, API keys, tokens. KMS is for encryption keys, not secrets.

Multi-region keys have the same key material - the key exists identically in multiple regions. This is intentional for DR, but it means a compromise in any region compromises all.

Automatic rotation has no downtime - the KeyId stays the same, old data remains decryptable, new encryption uses new material. This is one of KMS's better features.

CloudTrail logs every KMS operation - Encrypt, Decrypt, GenerateDataKey, CreateGrant, RevokeGrant, and more. This is a critical audit trail for compliance.

Files
policies/lab31-key-policy.json - the key policy

key-info.json - describe-key output

grants.json - list-grants output (after revoke)

encrypted.b64 - the direct KMS ciphertext from the small-file test

ciphertext.bin - the decoded binary ciphertext

data-encrypted.bin - AES-256 ciphertext of the bulk data

data-iv.bin - the initialization vector for the AES encryption

encrypted-datakey.b64 - the KMS-encrypted data key

recovered-datakey.bin - the plaintext data key recovered from KMS

Note: The plaintext data key files (datakey.json, datakey.bin) were intentionally deleted to demonstrate envelope encryption. Only the KMS-encrypted version remains.

Cleanup
aws kms delete-alias --alias-name alias/lab31-demo-key
aws kms schedule-key-deletion --key-id cfa447a7-7122-4c36-a619-e41fbe3b8ba3 --pending-window-in-days 7

Key deletion has a mandatory 7-day waiting period (can be up to 30 days). During this window, the key cannot be used, but the deletion can be cancelled. After the window, the key material is destroyed and encryption is permanently lost.

AWS-managed keys are never deleted by you.
