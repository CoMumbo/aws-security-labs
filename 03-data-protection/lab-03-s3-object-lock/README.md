# Lab 3.3 - S3 Object Lock + Versioning

**Date:** 2026-10-19
**Goal:** Understand S3 versioning, Object Lock (WORM), and how they defend against ransomware and accidental deletion. Prove that versioning alone does not prevent deliberate deletion, but Object Lock does.

## Objective

1. Create a bucket with Object Lock enabled at creation (mandatory)
2. Upload multiple versions of a file and verify both are preserved
3. Delete the file and observe it becomes a delete marker
4. Remove the delete marker and recover the file
5. Configure default Object Lock retention (GOVERNANCE mode, 1 day)
6. Attempt to delete a locked object without bypass -> AccessDenied
7. Delete a locked object with --bypass-governance-retention -> Success
8. Apply and remove a legal hold

## Concept: Versioning

When versioning is enabled on a bucket, S3 preserves every version of every object. Uploads never overwrite - they create a new version with a new VersionId. Deletes create a "delete marker" as the new latest version, which makes the object appear deleted without actually removing any data.

Versioning states:
- **Unversioned** (default) - uploads overwrite, deletes destroy
- **Enabled** - uploads preserve history, deletes create markers
- **Suspended** - can be set after enabling; uploads go to a null version, deletes create markers, but old versions are preserved

Once enabled, versioning can be suspended but never returned to unversioned. The bucket will always be versioned from that point forward.

## Concept: Object Lock

Object Lock is a WORM (Write Once, Read Many) mechanism. Once enabled at bucket creation, it cannot be disabled. It provides two independent protections:

### 1. Retention

A fixed period during which an object version cannot be deleted or overwritten. Two modes:

- **GOVERNANCE mode** - privileged users with `s3:BypassGovernanceRetention` can override
- **COMPLIANCE mode** - **nobody** can override, not even the root account, not even AWS Support

Retention can be set as a default on the bucket (applies to every new object), or per-object at upload time.

### 2. Legal Hold

An indefinite lock independent of retention. Toggled on/off with `s3:PutObjectLegalHold`. Used for litigation, investigations, or regulatory holds where retention period is unknown.

An object with both retention and legal hold must satisfy both conditions before deletion is possible.

## Concept: The Cost of Getting This Wrong

Object Lock cannot be enabled on an existing bucket. If you decide later that you need it, you must:
1. Create a new bucket with Object Lock enabled
2. Copy data from old to new bucket
3. Update all application references

This is why compliance and security teams often default to creating all buckets with Object Lock enabled at creation, even if not immediately used. The cost of an unused feature is zero; the cost of retrofitting is high.

## What Was Built

| Resource | Value |
|---|---|
| Bucket name | lab33-objectlock-803964124082-20261019130206 |
| Object Lock | Enabled at creation |
| Versioning | Enabled (automatic with Object Lock) |
| Default retention | GOVERNANCE, 1 day |
| Test file | file.txt (2 versions: v1 22 bytes, v2 32 bytes) |
| Delete marker | Created then removed |
| Locked file | locked.txt (retention + legal hold tested) |
| Legal hold | Set ON, then OFF |
| Bypass test | Failed without --bypass-governance-retention, succeeded with it |

## Setup Commands

### 1. Create bucket with Object Lock enabled

$bucketName = "lab33-objectlock-803964124082-$(Get-Date -Format 'yyyyMMddHHmmss')"
aws s3api create-bucket --bucket $bucketName --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1 --object-lock-enabled-for-bucket

The --object-lock-enabled-for-bucket flag is mandatory at creation. Without it, the bucket cannot support Object Lock later.

### 2. Verify Object Lock and versioning

aws s3api get-object-lock-configuration --bucket $bucketName
aws s3api get-bucket-versioning --bucket $bucketName

Returned:

{
    "ObjectLockConfiguration": {
        "ObjectLockEnabled": "Enabled"
    }
}

{
    "Status": "Enabled",
    "MFADelete": "Disabled"
}

Versioning is automatically enabled when Object Lock is on. You cannot have Object Lock without versioning.

## Versioning Demonstration

### Upload v1 and v2

"Version 1 of my file" | Out-File -Encoding ascii file.txt
aws s3 cp file.txt "s3://$bucketName/file.txt"

"Version 2 - I changed the file" | Out-File -Encoding ascii file.txt
aws s3 cp file.txt "s3://$bucketName/file.txt"

### Verify both versions exist

aws s3api list-object-versions --bucket $bucketName --prefix file.txt

Returned:

| VersionId | Size | IsLatest | LastModified |
|---|---|---|---|
| foIohDGX7z6I77Mhmho57WSuCgM9wuof | 32 bytes | True | 2026-10-19T10:03:25Z (v2) |
| AkwJo3H1Uv9tlNvzu7Cwbtq.dDUgSvlU | 22 bytes | False | 2026-10-19T10:03:15Z (v1) |

Both versions preserved.

### Delete the file (creates delete marker)

aws s3 rm "s3://$bucketName/file.txt"

Download attempt:

aws s3 cp "s3://$bucketName/file.txt" downloaded.txt

Result: 404 Not Found. The file appears deleted.

But list-object-versions shows:

- Two versions (both IsLatest: false)
- One delete marker (IsLatest: true)

### Recover by deleting the delete marker

aws s3api delete-object --bucket $bucketName --key file.txt --version-id 8jL3bHsc6QsP31_YlcOskrZJaUokt2GL

This is a soft delete of the marker. It does not delete the actual file version.

Download again:

aws s3 cp "s3://$bucketName/file.txt" restored.txt
Get-Content restored.txt

Result: "Version 2 - I changed the file"

The file is fully restored. The accidental delete was recoverable.

## Object Lock Demonstration

### Configure default retention

aws s3api put-object-lock-configuration --bucket $bucketName --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":1}}}'

Every new object is now automatically locked for 1 day in GOVERNANCE mode.

### Upload a locked file

"Locked data that cannot be deleted for 24 hours" | Out-File -Encoding ascii locked.txt
aws s3 cp locked.txt "s3://$bucketName/locked.txt"

### Attempt to delete the locked file

aws s3api delete-object --bucket $bucketName --key locked.txt --version-id 6bXGdMcDeWv4BPPmQ4oh2IOwwVCxBWbX

Result:

An error occurred (AccessDenied) when calling the DeleteObject operation: Access Denied because object protected by object lock.

The file cannot be deleted. Not by admin, not by root, not by anyone without the bypass permission.

### Apply a legal hold

aws s3api put-object-legal-hold --bucket $bucketName --key locked.txt --legal-hold Status=ON

Verify:

aws s3api get-object-legal-hold --bucket $bucketName --key locked.txt

Returned: Status: ON

The object now has both retention AND legal hold. Deletion requires:
1. Bypass retention (s3:BypassGovernanceRetention permission)
2. Remove legal hold (s3:PutObjectLegalHold permission)
3. Standard delete (s3:DeleteObject permission)

Three separate permissions required.

### Remove the legal hold (allowed by our admin user)

aws s3api put-object-legal-hold --bucket $bucketName --key locked.txt --legal-hold Status=OFF

Legal hold removed. Retention still active.

### Bypass the retention (requires s3:BypassGovernanceRetention)

aws s3api delete-object --bucket $bucketName --key locked.txt --version-id 6bXGdMcDeWv4BPPmQ4oh2IOwwVCxBWbX --bypass-governance-retention

Result: Success. The object is deleted.

The --bypass-governance-retention flag requires the s3:BypassGovernanceRetention permission. Our admin-zeff user has AdministratorAccess, which includes this. A user without that permission would fail even with the flag.

## GOVERNANCE vs COMPLIANCE Mode

| Aspect | GOVERNANCE | COMPLIANCE |
|---|---|---|
| Can be bypassed with permission | Yes | No |
| Can be bypassed by root | With the flag | No |
| Can be bypassed by AWS Support | No | No |
| Retention can be shortened before expiry | With bypass permission | No |
| Use case | Operational flexibility, ransomware defense | Regulatory compliance, legal hold |

COMPLIANCE mode is absolute. Once locked, no person, process, or AWS service can delete the object until the retention expires. This makes it suitable for SEC 17a-4, FINRA, CFTC, and other regulatory retention requirements.

The trade-off: if you lock a file in COMPLIANCE mode for 10 years by mistake, you cannot undo it. AWS Support cannot undo it. The object is not deletable until 10 years from the lock date.

## Key Insights

### 1. Versioning Is Necessary but Not Sufficient

Versioning protects against:
- Accidental deletion (delete markers are recoverable)
- Overwriting files (old versions preserved)
- Some forms of ransomware (if the ransomware does not delete all versions)

Versioning does NOT protect against:
- A privileged attacker calling DeleteObjectVersion on every version
- An insider with permissions deliberately destroying all versions

### 2. Object Lock Is the Ransomware Defense

With Object Lock in place:
- An attacker with admin credentials cannot delete locked objects
- The attacker can only wait for retention to expire
- For COMPLIANCE mode, not even waiting helps if retention is long enough

Combined with cross-region replication to another account with Object Lock, this provides true ransomware resilience: even if the entire source account is compromised, the replica is immutable.

### 3. Two Modes, Two Purposes

GOVERNANCE mode:
- Operational flexibility
- Backup immutability with escape hatch
- Ransomware defense (attacker likely lacks BypassGovernanceRetention)
- Can be shortened by admin if needed

COMPLIANCE mode:
- Regulatory compliance
- Absolute immutability
- Cannot be shortened even by admin
- Suitable for WORM archival

### 4. Legal Hold Is Independent

Legal hold is not a retention period. It is an indefinite lock that requires explicit release. Use it when:
- Litigation is ongoing and retention period is unknown
- An investigation is active
- Regulatory hold is in effect without a defined end date

Legal hold + retention together = strongest protection, requiring multiple distinct permissions to disable.

## Real-World Application

### Ransomware Defense

The standard pattern for ransomware-resistant backups in AWS:

1. Backup bucket has Object Lock enabled at creation
2. Default retention in COMPLIANCE mode for 30-90 days
3. Cross-region replication to a separate account with its own Object Lock
4. IAM policies prevent deletion at the source account
5. Even if the source account is fully compromised, replicas in the target account remain locked

The ransomware attacker's success depends on finding and destroying backups. With Object Lock in COMPLIANCE mode, they cannot. They can only encrypt the live data; the locked backups become the recovery point.

### Regulatory Compliance

Financial services regulations like SEC 17a-4(f) require:
- WORM storage
- Retention periods from 3 to 10 years
- Immediate accessibility for regulators

S3 Object Lock in COMPLIANCE mode satisfies these requirements. Many organizations use S3 Object Lock with retention in the years range for regulatory archives.

### Legal Hold for Litigation

When litigation is filed, legal departments issue litigation holds. In AWS, this means:
1. Enable legal hold on all relevant objects
2. Legal hold prevents deletion while the case is active
3. When the case closes, release the legal hold

This is much cheaper than moving data to a separate WORM system, and it's auditable via CloudTrail.

### The Multi-Account Pattern

The strongest defense is:
- Primary data in Account A (versioning + Object Lock GOVERNANCE)
- Cross-account replication to Account B (separate organization)
- Account B has Object Lock COMPLIANCE mode with 90-day retention
- Account B has different IAM admins (separation of duties)
- A compromise in Account A cannot touch Account B's locked copies

This is the pattern AWS Backup, Veeam, Rubrik, and Cohesity all use for ransomware-resistant backups.

## Lessons / Gotchas

1. Object Lock must be enabled at bucket creation. It cannot be added to existing buckets. Plan ahead.

2. Versioning is automatically enabled when Object Lock is on. You cannot have one without the other.

3. Delete marker is not the same as delete. Deleting an object without a version ID adds a marker; the data is still there. Deleting with a version ID removes that specific version permanently.

4. GOVERNANCE mode is bypassable with permission. If you need true immutability, use COMPLIANCE mode.

5. COMPLIANCE mode cannot be shortened or removed. Locking an object for 10 years in COMPLIANCE mode means 10 years, period. AWS Support cannot help.

6. Legal hold requires the s3:PutObjectLegalHold permission. It is separate from retention.

7. Multi-permission delete protection - with retention + legal hold, an attacker needs three separate IAM permissions to destroy data. This is defense in depth.

8. CloudTrail logs every delete-object call, whether it succeeds or fails. The audit trail shows attempts.

9. Versioning increases storage costs. Every version of every object is billed. Lifecycle rules can expire old versions to control cost.

10. Object Lock does not replace backup. It complements backup. The distinction: backup is about recovery, Object Lock is about immutability. You need both.

## Files

- object-lock-config.json - bucket Object Lock configuration
- versions.json - all object versions after the lab
- retention.json - the locked object retention details

## Cleanup

The bucket must be emptied before it can be deleted. Note that locked objects cannot be deleted until their retention expires.

$bucketName = "lab33-objectlock-803964124082-20261019130206"

# List and remove all delete markers first
aws s3api list-object-versions --bucket $bucketName --query "DeleteMarkers[].{Key:Key,VersionId:VersionId}" --output json

# For each delete marker, remove it
# Then remove all versions (may fail if locked)
# Then remove the bucket

If any objects are locked, wait for retention to expire or use --bypass-governance-retention (for GOVERNANCE mode objects) before deleting.

After the 24-hour retention from this lab expires, the entire bucket can be deleted:
aws s3 rm "s3://$bucketName" --recursive --include "*" --exclude ""
aws s3 rb "s3://$bucketName"

If deletion fails due to retention, either wait or bypass:
aws s3api delete-object --bucket $bucketName --key <key> --version-id <version-id> --bypass-governance-retention

## Real-World Application

Object Lock is the primary mechanism for making AWS backups ransomware-resistant. The pattern:

- Backup tools (AWS Backup, Veeam, Rubrik) use Object Lock in COMPLIANCE mode
- Retention is set to match the recovery point objective (RPO) and recovery time objective (RTO)
- Cross-account replication adds a second layer (source account compromise does not affect target account locks)
- CloudTrail + Config monitor for any attempt to modify Object Lock configuration

Without Object Lock, an attacker with stolen credentials can:
1. Delete all backups
2. Encrypt all live data
3. Demand ransom with no recovery option

With Object Lock in COMPLIANCE mode, steps 1 and 2 partially succeed (live data may be encrypted), but the backups are intact. Recovery is possible. This is the difference between a 3-day incident and a 3-month crisis.

Organizations often discover Object Lock too late - after they need it. The best practice is to enable it on every backup bucket from day one, even if retention is short. Adding it retroactively requires recreating the bucket and copying data, which is often not feasible.
