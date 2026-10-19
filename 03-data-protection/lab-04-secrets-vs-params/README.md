# Lab 3.4 - Secrets Manager vs Parameter Store

**Date:** 2026-10-19
**Goal:** Understand the two AWS services for storing secrets and configuration. Compare their features, cost, versioning, rotation, and hierarchy by building the same secret in both and observing the differences.

## Objective

1. Store a database password in Secrets Manager with versioning
2. Retrieve current and previous versions by version ID
3. Store the same password in Parameter Store as a SecureString
4. Prove that SecureString requires explicit decryption
5. Update and retrieve historical versions in both services
6. Build a parameter hierarchy and retrieve by path
7. Document the feature matrix and cost model

## Concept: The Two Services

### AWS Secrets Manager

- Purpose-built for secrets
- Encrypted at rest with KMS (AWS-managed or customer-managed)
- Encrypted in transit (TLS)
- Native rotation support (Lambda-driven, pre-built for RDS/Redshift/DocumentDB and others)
- Version stages: AWSCURRENT, AWSPREVIOUS, AWSPENDING
- Cross-account sharing via resource policies
- Charges $0.40 per secret per month + API call charges
- Maximum secret size: 64 KB

### AWS Systems Manager Parameter Store

- Purpose-built for configuration, with a SecureString type for sensitive values
- Plain (String) and StringList parameters stored in plaintext
- SecureString parameters encrypted with KMS
- No built-in rotation (manual version management)
- Numeric version history, no stage names
- Hierarchical path-based namespace
- Free tier: 10,000 Standard parameters, unlimited API calls
- Advanced tier: $0.05 per parameter per month
- Maximum parameter size: 8 KB (Standard), 8 KB or higher (Advanced)

## The Critical Distinction

| Need | Use |
|---|---|
| Database password with automatic rotation | Secrets Manager |
| API key with automatic rotation | Secrets Manager |
| Cross-account secret sharing | Secrets Manager |
| Config value (non-sensitive) | Parameter Store (String) |
| Config value (sensitive, no rotation needed) | Parameter Store (SecureString) |
| Hierarchical config tree | Parameter Store |
| Free tier for many parameters | Parameter Store |
| Password that changes regularly | Secrets Manager |
| Value that never changes (e.g. region name) | Parameter Store |

The general rule: **Secrets Manager for things that rotate; Parameter Store for things that don't.** Both can encrypt secrets, but only Secrets Manager has rotation built in.

## What Was Built

| Resource | Identifier |
|---|---|
| Secret: name | lab34/db-password |
| Secret: ARN | arn:aws:secretsmanager:eu-north-1:803964124082:secret:lab34/db-password-PDVk5U |
| Secret: version 1 (AWSPREVIOUS) | 0dfbc72a-cda5-4253-9770-36b75a4a0651 |
| Secret: version 2 (AWSCURRENT) | 310d4a0b-8012-4fd5-900f-f1d7b683d6d3 |
| Parameter: name | /lab34/db-password |
| Parameter: version 1 | MyParamStorePassword789! |
| Parameter: version 2 | UpdatedParam789! |
| Parameter tree | /lab34/app/database/{host,port,user} |

## Secrets Manager Demonstration

### Create a secret

aws secretsmanager create-secret --name lab34/db-password --description "Lab 3.4 database password" --secret-string "MySecretPassword123!"

Returned:

- ARN: arn:aws:secretsmanager:eu-north-1:803964124082:secret:lab34/db-password-PDVk5U
- VersionId: 0dfbc72a-cda5-4253-9770-36b75a4a0651

### Retrieve the current secret

aws secretsmanager get-secret-value --secret-id lab34/db-password --query "SecretString" --output text

Returned: MySecretPassword123!

### Update the secret

aws secretsmanager put-secret-value --secret-id lab34/db-password --secret-string "MyNewPassword456!"

Returned:

- VersionId: 310d4a0b-8012-4fd5-900f-f1d7b683d6d3
- VersionStages: ["AWSCURRENT"]

### List all versions

aws secretsmanager list-secret-version-ids --secret-id lab34/db-password

Returned:

| VersionId | Stages |
|---|---|
| 310d4a0b-8012-4fd5-900f-f1d7b683d6d3 | AWSCURRENT |
| 0dfbc72a-cda5-4253-9770-36b75a4a0651 | AWSPREVIOUS |

Both versions tracked, with stage labels indicating which is active.

### Retrieve the previous version

aws secretsmanager get-secret-value --secret-id lab34/db-password --version-id 0dfbc72a-cda5-4253-9770-36b75a4a0651 --query "SecretString" --output text

Returned: MySecretPassword123! (the old value is still accessible)

This enables safe rollback: if the new password breaks something, retrieve the old version by its version ID.

## Parameter Store Demonstration

### Create a SecureString parameter

aws ssm put-parameter --name "/lab34/db-password" --value "MyParamStorePassword789!" --type SecureString --description "Lab 3.4 secure parameter"

Returned: Version 1, Tier Standard

### Retrieve WITHOUT decryption

aws ssm get-parameter --name "/lab34/db-password" --query "Parameter.Value" --output text

Returned: AQICAHhfEl6P0CUAll7CxN1E6sMQlwitHFYdHr47... (long base64 ciphertext)

The default retrieval returns the KMS ciphertext blob. The parameter is encrypted but the caller must explicitly request decryption.

### Retrieve WITH decryption

aws ssm get-parameter --name "/lab34/db-password" --with-decryption --query "Parameter.Value" --output text

Returned: MyParamStorePassword789!

KMS is called to decrypt the ciphertext. The permission required is `kms:Decrypt` on the KMS key used for the parameter.

**Critical difference:** Parameter Store default-denies decryption. Secrets Manager default-allows plaintext retrieval (the API call itself is the gate). This means a misconfigured application that accidentally logs a Parameter Store value gets the ciphertext; a misconfigured application that logs a Secrets Manager value gets plaintext.

### Update the parameter

aws ssm put-parameter --name "/lab34/db-password" --value "UpdatedParam789!" --type SecureString --overwrite

Returned: Version 2

### View version history

aws ssm get-parameter-history --name "/lab34/db-password"

Returned: Both versions with their KMS ciphertext blobs and timestamps. Values are not masked when queried via CLI (only via console).

### Retrieve a specific version

aws ssm get-parameter --name "/lab34/db-password:1" --with-decryption --query "Parameter.Value" --output text

Returned: MyParamStorePassword789! (version 1's value)

The `:N` suffix in the parameter name retrieves a specific version. Note: the `--version` flag exists but conflicts with the global `aws --version` flag in some CLI versions, making `name:version` the more reliable syntax.

## Parameter Store Hierarchy

### Create a tree of parameters

aws ssm put-parameter --name "/lab34/app/database/host" --value "db.example.com" --type String
aws ssm put-parameter --name "/lab34/app/database/port" --value "5432" --type String
aws ssm put-parameter --name "/lab34/app/database/user" --value "appuser" --type String

### Retrieve by path

aws ssm get-parameters-by-path --path "/lab34/app/database" --query "Parameters[].{Name:Name,Value:Value}" --output table

Returned:

| Name | Value |
|---|---|
| /lab34/app/database/host | db.example.com |
| /lab34/app/database/port | 5432 |
| /lab34/app/database/user | appuser |

One API call retrieves the entire configuration tree. This is a critical operational feature - applications retrieve their full config in one call at startup.

Secrets Manager has no equivalent. Each secret must be retrieved by its exact name. To get three secrets, three API calls are required.

## Feature Comparison Matrix

| Feature | Secrets Manager | Parameter Store |
|---|---|---|
| Free tier | None | 10,000 Standard parameters |
| Cost | $0.40/secret/month | Free (Standard) |
| Max size | 64 KB | 8 KB (Standard) |
| Encrypted at rest | Yes (required) | Yes (SecureString only) |
| Encrypted in transit | Yes | Yes |
| Built-in rotation | Yes (Lambda) | No |
| Version stages | AWSCURRENT/AWSPREVIOUS/AWSPENDING | Numeric only |
| Hierarchy | No | Yes (paths) |
| Bulk retrieval | No | Yes (by path) |
| Cross-account sharing | Yes (resource policy) | Limited (via RAM) |
| CloudTrail logging | Yes | Yes |
| API calls | Per secret | Bulk available |
| Auto-expiration | No | Yes (parameter expiration) |
| Compliance evidence | Rotation history | Change history |

## When to Choose Which

### Choose Secrets Manager when

- The credential rotates (database passwords, API keys, OAuth tokens)
- You need native rotation with pre-built Lambdas for RDS/Redshift/DocumentDB
- You share secrets cross-account
- You need explicit version stages (AWSCURRENT vs AWSPREVIOUS)
- You want compliance evidence of when each version was active

### Choose Parameter Store when

- The value is configuration, not a secret (feature flags, endpoints, region names)
- You need hierarchical organization
- You need bulk retrieval by path
- You want a free tier (many small config values)
- You manage secrets manually (no rotation needed)
- You need cross-region/cross-account config sharing via shared parameters

### Use both

A common enterprise pattern: **Secrets Manager for the database password, Parameter Store for everything else.** The application retrieves the password from Secrets Manager and the connection string (host, port, database name) from Parameter Store.

## Real-World Application

### The Blue/Green Deployment Pattern

During a database password rotation:
1. Secrets Manager starts the rotation Lambda
2. Lambda creates a new password, tagged as AWSPENDING
3. Lambda updates the database with the new password
4. Lambda tests the new password (login attempt)
5. Lambda promotes AWSPENDING to AWSCURRENT
6. AWSPREVIOUS keeps the old password for rollback

Applications always read AWSCURRENT. During the brief window where AWSPENDING is not yet AWSCURRENT, the app continues using the old password. This is why rotation is safe.

Manual rotation (Parameter Store) has no such safety net. You change the value, and the app breaks the next time it connects.

### The Multi-Account Pattern

A central account holds all the database credentials for the organization:
1. Secrets Manager secrets are created in the central account
2. A resource policy grants cross-account access to specific application accounts
3. The application account retrieves via `get-secret-value`
4. CloudTrail in both accounts logs every retrieval

Parameter Store does not support this pattern cleanly. Advanced parameters can be shared via AWS Resource Access Manager (RAM), but the pattern is less common.

### The Config-as-Code Pattern

Parameter Store is the natural home for application configuration that is:
- Version-controlled in Terraform/CloudFormation
- Different per environment (/myapp/dev/..., /myapp/prod/...)
- Retrieved at startup via `get-parameters-by-path`

A typical Terraform setup creates 20-50 parameters in a path tree. The application retrieves them all with one API call.

## Lessons / Gotchas

1. **SecureString requires `--with-decryption`.** Without the flag, you get the KMS ciphertext, not the plaintext. This is a common source of "why doesn't my app see the right value" bugs.

2. **Secrets Manager versioning uses UUIDs.** Version IDs are random strings, not sequential numbers. You retrieve old versions by UUID.

3. **Parameter Store versioning uses integers.** Versions are 1, 2, 3... The `:N` suffix in the parameter name retrieves a specific version.

4. **The `--version` flag conflicts with `aws --version`.** For `ssm get-parameter`, use the `name:version` syntax instead of the flag.

5. **Parameter Store has no rotation.** If you need rotation, use Secrets Manager. Manual rotation is error-prone and un-audited (except for the version number change).

6. **The rotation Lambda is custom.** Secrets Manager provides templates for RDS and a few others, but for custom databases you write the Lambda. The four-step flow (create/set/test/finish) must be implemented carefully.

7. **Both services are audited by CloudTrail.** `GetSecretValue` and `GetParameter` calls are logged. This is essential for compliance and incident response.

8. **Neither service is a substitution for the other's primary use case.** Secrets Manager is not a config store; Parameter Store is not a rotation engine. Use both for their strengths.

9. **Cross-account sharing is different.** Secrets Manager uses a resource policy. Parameter Store uses RAM shared parameters (advanced feature). The operational patterns are not interchangeable.

10. **KMS integration is automatic.** Both services use KMS under the hood. The KMS key ID can be specified at creation, or the default AWS-managed key is used. Rotation of the KMS key is separate from rotation of the secret itself.

11. **Cost is the biggest differentiator at scale.** 100 secrets × $0.40 = $40/month. 100 parameters = $0 (Standard tier). For large parameter counts, Parameter Store is dramatically cheaper.

## Files

- secret-info.json - describe-secret output
- param-history.json - parameter version history
- param-tree.json - hierarchical parameter retrieval

## Cleanup

aws secretsmanager delete-secret --secret-id lab34/db-password --force-delete-without-recovery
aws ssm delete-parameter --name "/lab34/db-password"
aws ssm delete-parameter --name "/lab34/app/database/host"
aws ssm delete-parameter --name "/lab34/app/database/port"
aws ssm delete-parameter --name "/lab34/app/database/user"

Secrets Manager charges continue until the secret is fully deleted. The `--force-delete-without-recovery` flag skips the default 30-day recovery window; use it for test resources. For production secrets, use the default recovery window so an accidental delete can be undone.

Parameter Store has no recovery window. Deletion is immediate and permanent. The version history is also deleted. There is no "undelete" for a parameter.

## Real-World Application

### When Secrets Manager Fails: The Rotation Lambda Debugging Pattern

If rotation fails (Lambda error, database unavailable, wrong IAM permissions), the secret gets stuck in a state:
- AWSCURRENT still points to the old password
- AWSPENDING has a new password that the database doesn't accept
- Applications continue using the old password (correct behavior)
- But the rotation Lambda keeps failing

Debugging requires:
1. Check CloudWatch Logs for the rotation Lambda
2. Look for errors in the createSecret, setSecret, or testSecret step
3. Verify the Lambda has permissions for Secrets Manager, RDS, and KMS
4. Verify the database accepts the new password

The safe recovery is to force the rotation to succeed (fix the Lambda, trigger rotation again) or manually set AWSCURRENT to the known-good password.

### When Parameter Store Fails: The Path-Tree Consistency Problem

If an application relies on a parameter tree, and one parameter in the tree is deleted or renamed, the application may fail at startup. This is a common issue with `get-parameters-by-path` - if the tree is expected to have N parameters, but one is missing, the app starts with partial config.

The fix is defensive coding:
- Validate that all required parameters are present after retrieval
- Use a manifest parameter that lists all expected parameter names
- Use Terraform's `for_each` to manage parameter creation atomically

Neither service has "atomic tree updates." This is a gap that monitoring and defensive coding must fill.

## The Bottom Line

- **Secrets Manager** = secret + rotation + cross-account + audit
- **Parameter Store** = config + hierarchy + free + audit
- **Both use KMS** = both are encrypted at rest (for SecureString)
- **Both are logged** = both have full CloudTrail trails
- **Both have versioning** = but different mechanics (UUID vs integer)
- **Both are essential** = neither replaces the other

For any AWS account with a database, an API key, or a secret that changes: use Secrets Manager. For the rest: use Parameter Store.
