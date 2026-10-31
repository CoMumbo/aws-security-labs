# Lab 4.4 - AWS Config - Continuous Compliance and Auto-Remediation

**Date:** 2026-10-30
**Goal:** Set up AWS Config to record resource changes, evaluate compliance rules, and query the resource configuration history. This is a hands-on lab - Config works in this account, unlike the SCP-blocked detection services.

## Objective

1. Create the Config S3 bucket and IAM role
2. Create the configuration recorder and delivery channel
3. Start recording and verify resource discovery
4. Add compliance rules (ENCRYPTED_VOLUMES, S3_BUCKET_PUBLIC_READ_PROHIBITED)
5. Observe compliance evaluation against real resources
6. Document the INSUFFICIENT_DATA behavior and evaluation timing
7. Verify S3 bucket compliance with the Block Public Access fix from Lab 3.2

## Concept: What AWS Config Is

AWS Config is a continuous configuration tracking and compliance service. It does three things:

### 1. Records resource changes

Every time a resource is created, modified, or deleted, Config records a Configuration Item (CI). The CI captures the full configuration at that moment. You can query the history to see what changed and when.

Examples:
- A security group rule was removed at 14:32 UTC
- An S3 bucket policy was updated at 09:15 UTC
- An EBS volume was created with encryption at 10:45 UTC

### 2. Evaluates compliance rules

Config rules check resource configurations against a desired state. There are three kinds:

- **AWS Managed Rules** - hundreds of pre-built rules (e.g., ENCRYPTED_VOLUMES, S3_BUCKET_PUBLIC_READ_PROHIBITED, IAM_USER_MFA_ENABLED)
- **Custom Lambda Rules** - you write the rule logic in Lambda
- **Conformance Packs** - bundles of rules for a standard (e.g., PCI DSS, HIPAA)

Each rule reports PASSED, FAILED, or INSUFFICIENT_DATA per resource.

### 3. Provides resource inventory

Config maintains a complete inventory of every resource in the account, with the ability to:
- Query by resource type ("show me all S3 buckets")
- Query by tag ("show me all resources tagged Environment=prod")
- See historical configuration (not just current state)

This is the "CMDB" (configuration management database) for AWS.

## Concept: Config vs Security Hub vs GuardDuty

| Aspect | AWS Config | Security Hub | GuardDuty |
|---|---|---|---|
| Purpose | Configuration tracking + compliance | Aggregation + compliance score | Threat detection |
| Data source | Resource configurations | Findings from other services | CloudTrail, VPC Flow, DNS |
| Real-time? | Near real-time (per resource change) | Aggregates findings | Near real-time |
| Detection | Compliance drift | Aggregated findings | Malicious activity |
| Cost | Per resource recorded + per rule | Per check + tier | Per GB analyzed |

All three are complementary. Config tracks configuration, Security Hub aggregates findings, GuardDuty detects threats.

## What Was Built

| Resource | Value |
|---|---|
| Config S3 bucket | lab44-config-803964124082-20261030093851 |
| Config role | arn:aws:iam::803964124082:role/Lab44ConfigRole |
| Role policy | AWS_ConfigRole (AWS-managed) |
| Configuration recorder | lab44-recorder |
| Delivery channel | lab44-channel |
| Rule 1 | lab44-encrypted-volumes (ENCRYPTED_VOLUMES) |
| Rule 2 | lab44-s3-public-read (S3_BUCKET_PUBLIC_READ_PROHIBITED) |
| Compliance (S3 rule) | COMPLIANT |
| Compliance (EBS rule) | INSUFFICIENT_DATA (pending evaluation) |

## Setup Commands

### 1. Create the S3 bucket

$configBucket = "lab44-config-803964124082-$(Get-Date -Format 'yyyyMMddHHmmss')"
aws s3api create-bucket --bucket $configBucket --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1

### 2. Create the IAM trust policy and role

File: policies/config-trust-policy.json

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
aws iam create-role --role-name Lab44ConfigRole --assume-role-policy-document file://policies/config-trust-policy.json
aws iam attach-role-policy --role-name Lab44ConfigRole --policy-arn "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"

The AWS_ConfigRole policy grants Config permission to read all resources and write to the S3 bucket.

3. Create the bucket policy
File: policies/config-bucket-policy.json

json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::lab44-config-803964124082-20261030093851"
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::lab44-config-803964124082-20261030093851/AWSLogs/803964124082/Config/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
Apply:

aws s3api put-bucket-policy --bucket $configBucket --policy file://policies/config-bucket-policy.json

Same pattern as CloudTrail - both statements required.

4. Create the configuration recorder
aws configservice put-configuration-recorder --configuration-recorder name=lab44-recorder,roleARN=arn:aws:iam::803964124082:role/Lab44ConfigRole --recording-group allSupported=true,includeGlobalResourceTypes=true

Flags:

allSupported=true - record all resource types

includeGlobalResourceTypes=true - also record IAM users/roles

5. Create the delivery channel
aws configservice put-delivery-channel --delivery-channel name=lab44-channel,s3BucketName=lab44-config-803964124082-20261030093851

6. Start recording
aws configservice start-configuration-recorder --configuration-recorder-name lab44-recorder

Verify:

aws configservice describe-configuration-recorder-status --configuration-recorder-names lab44-recorder

Returned:

{
"Name": "lab44-recorder",
"Recording": true,
"LastStatus": "SUCCESS",
"LastError": null
}

Adding Compliance Rules
Rule 1 - Encrypted Volumes
File: policies/encrypted-volumes-rule.json

json
{
  "ConfigRuleName": "lab44-encrypted-volumes",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "ENCRYPTED_VOLUMES"
  }
}
Apply:

aws configservice put-config-rule --config-rule file://policies/encrypted-volumes-rule.json

Rule 2 - S3 Public Read Prohibited
File: policies/s3-public-read-rule.json

json
{
  "ConfigRuleName": "lab44-s3-public-read",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}
Apply:

aws configservice put-config-rule --config-rule file://policies/s3-public-read-rule.json

Compliance Results
After ~2 minutes, first evaluation:

Rule    Compliance    Reason
lab44-s3-public-read    COMPLIANT    Both buckets have Block Public Access enabled
lab44-encrypted-volumes    INSUFFICIENT_DATA    No EBS volumes existed at evaluation time
The S3 rule immediately evaluated and passed. This confirms the Block Public Access fix from Lab 3.2 is still in place and enforced.

Creating an Encrypted EBS Volume (to trigger the EBS rule)
To demonstrate the EBS rule working, an EBS volume was created:

aws ec2 create-volume --availability-zone eu-north-1a --size 1 --volume-type gp3 --tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=lab44-encrypted-test}]"

Returned:

{
"VolumeId": "vol-044835f95c0125cef",
"Encrypted": true,
"Size": 1,
"VolumeType": "gp3"
}

Critical observation: The volume was created with Encrypted: true even though we did not pass --encrypted. This is the EBS default encryption from Lab 3.6 working automatically.

The INSUFFICIENT_DATA Lesson
Even after creating the encrypted volume, the ENCRYPTED_VOLUMES rule continued to report INSUFFICIENT_DATA for several minutes.

This is expected behavior:

Config rules with resource-type triggers evaluate on a schedule (every 15 minutes or on a change event)

The first evaluation for a new rule can take up to 15 minutes

INSUFFICIENT_DATA appears when: (a) no evaluation has happened yet, (b) no resources of the relevant type exist, or (c) the rule needs permissions it does not have

Why this matters: Config is not real-time. It is near-real-time for resource discovery, but compliance evaluation is periodic. For real-time enforcement, use EventBridge rules that fire on resource change events, not Config rules.

Resource Discovery
Config discovered both S3 buckets in the account:

aws configservice list-discovered-resources --resource-type AWS::S3::Bucket

Returned:

lab41-cloudtrail-logs-803964124082-20261030075911

lab44-config-803964124082-20261030093851

This proves Config is tracking every resource. In a production account with hundreds of buckets, all would be tracked.

Concept: Configuration History
For any resource, Config provides a timeline of changes:

aws configservice get-resource-config-history --resource-type AWS::S3::Bucket --resource-name <bucket-name>

This returns ConfigurationItems, each with:

captureTime (when the snapshot was taken)

configurationItemStatus (OK, ResourceDiscovered, ResourceNotRecorded, etc.)

configuration (the full resource config at that moment)

This is the "time machine" - you can see what a resource looked like at any point in time.

Concept: Auto-Remediation
Config can fix non-compliant resources automatically. The pattern:

Config rule evaluates a resource and finds it non-compliant

Config triggers a remediation action

The remediation action is one of:

SSM Automation document (preferred for AWS-managed resources)

Lambda function (for custom logic)

The action fixes the resource

Config re-evaluates and transitions the finding to COMPLIANT

Example remediation: Enable S3 Block Public Access
The rule: S3_BUCKET_PUBLIC_READ_PROHIBITED
The remediation: AWS-DisableS3BucketPublicReadWrite SSM Automation document

When the rule finds a bucket with public read access:

It triggers the SSM document

The document applies put-public-access-block to the bucket

The bucket becomes compliant

The finding transitions to COMPLIANT

This is the "self-healing" pattern. No human intervention required for known issues.

Configuring auto-remediation
aws configservice put-remediation-configurations --remediation-configurations '[{
"ConfigRuleName": "lab44-s3-public-read",
"TargetType": "SSM_DOCUMENT",
"TargetId": "AWS-DisableS3BucketPublicReadWrite",
"Automatic": true,
"MaximumAutomaticAttempts": 3,
"RetryAttemptSeconds": 60,
"Parameters": {
"AutomationAssumeRole": {"StaticValue": {"Values": ["arn:aws:iam::803964124082:role/Lab44ConfigRole"]}},
"S3BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}}
}
}]'

The Automatic: true flag means remediation runs without human approval. The MaximumAutomaticAttempts limits retries. ResourceValue: RESOURCE_ID passes the non-compliant bucket name to the SSM document.

Cost Model
Config costs:

Configuration items recorded - $0.003 per CI per region per month

Config rules evaluated - $0.001 per rule evaluation per region

Conformance packs - $0.001 per check per region per month

For a small account with 100 resources and 5 rules:

CIs: ~100 × $0.003 = $0.30/month

Rule evaluations: 5 × ~40 evaluations (every 15 min × 10 hours) × $0.001 = $0.20/month

Total: ~$0.50/month

For a large account with 10,000 resources and 50 rules, the cost scales to $50-100/month. Cost optimization:

Record only specific resource types (not allSupported)

Reduce rule evaluation frequency

Use Config Aggregator to consolidate multi-account costs

Lessons / Gotchas
Config requires an S3 bucket, IAM role, and bucket policy. All three are mandatory. Missing any causes silent failure.

Both bucket policy statements are required. s3:GetBucketAcl (to verify) and s3:PutObject (to write). Same as CloudTrail.

Config is not instant. The first rule evaluation can take 10-15 minutes. INSUFFICIENT_DATA is a common state during that time. Not an error.

INSUFFICIENT_DATA has three causes: (a) evaluation not yet run, (b) no resources of the type exist, (c) insufficient permissions. In this lab, the EBS rule showed INSUFFICIENT_DATA because there were initially no volumes, then again briefly after a volume was created (evaluation pending).

Config rules run on a schedule, not per change. The default is every 15 minutes for periodic rules. For change-triggered rules, use EventBridge rules instead.

allSupported=true is expensive for large accounts. Use specificResourceTypes to limit scope to what you actually want to track.

Config is the prerequisite for auto-remediation. SSM Automation documents can be triggered by Config when resources go non-compliant. This is the "self-healing" pattern.

The Config bucket accumulates data. After months of recording, the bucket can have hundreds of GB. Plan lifecycle policies (transition to Glacier after 90 days, delete after 1-7 years based on compliance requirements).

The S3 bucket for Config must not be the same as any S3 bucket being tracked. This creates a circular dependency. Use a dedicated bucket.

Config's compliance results are historical. The current compliance for a resource is the last evaluation. If the resource was fixed, the compliance updates on the next evaluation cycle (not immediately).

Files
policies/config-trust-policy.json - the Config service trust policy

policies/config-bucket-policy.json - the S3 bucket policy for Config delivery

policies/encrypted-volumes-rule.json - the EBS encryption rule

policies/s3-public-read-rule.json - the S3 public access rule

config-recorder.json - the recorder configuration

compliance-state.json - the current compliance state for both rules

discovered-buckets.json - the S3 buckets discovered by Config

Cleanup
Remove rules first, then the recorder, then the delivery channel, then the role and bucket:

aws configservice delete-config-rule --config-rule-name lab44-s3-public-read
aws configservice delete-config-rule --config-rule-name lab44-encrypted-volumes
aws configservice stop-configuration-recorder --configuration-recorder-name lab44-recorder
aws configservice delete-configuration-recorder --configuration-recorder-name lab44-recorder
aws configservice delete-delivery-channel --delivery-channel-name lab44-channel
aws iam detach-role-policy --role-name Lab44ConfigRole --policy-arn "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
aws iam delete-role --role-name Lab44ConfigRole
aws s3 rm "s3://lab44-config-803964124082-20261030093851" --recursive
aws s3api delete-bucket --bucket lab44-config-803964124082-20261030093851

Real-World Application
The Compliance Evidence Trail
Config is the primary evidence source for compliance audits:

"Prove that no S3 bucket has been public in the last year" - query Config's configuration history for all S3 buckets; verify that no PublicAccessBlockConfiguration was ever empty

"Prove that EBS encryption was enabled for all volumes created after date X" - query Config for all AWS::EC2::Volume resources; verify Encrypted: true on all created after the date

"Prove that CloudTrail has been continuously enabled" - query Config for AWS::CloudTrail::Trail; verify the trail's configuration was consistent over the time period

This is what auditors ask for. Config is the database that answers these questions.

The Continuous Compliance Program
A mature compliance program uses Config for:

Baseline rules - 50-200 AWS managed rules that represent the organization's security baseline

Conformance packs - bundles for specific frameworks (PCI, HIPAA, SOC 2)

Multi-account aggregation - Config Aggregator in the management account, aggregating all member accounts

Auto-remediation - SSM Automation for the top 20 known-issue remediations

Manual remediation workflow - the rest are assigned to owning teams via Security Hub tickets

This is the standard pattern for regulated AWS environments.

The Drift Detection Pattern
One of Config's most powerful uses: detecting drift from a known-good state.

Record the expected configuration of a resource (e.g., a security group should have exactly 3 rules)

Config tracks the actual configuration

When someone changes the configuration, Config records the change

A rule compares actual to expected

If they differ, the rule fires

This is how "infrastructure as code" organizations ensure that manual changes don't sneak in.

The Config + EventBridge Pattern
For real-time remediation (not 15-minute waits):

Config records a resource change

Config publishes a "Configuration Item Change Notification" event to EventBridge

EventBridge rule triggers on the specific change type

Lambda or SSM Automation reacts immediately

This bypasses Config's 15-minute evaluation cycle. Events fire within seconds.

The Combined Detection and Remediation Stack
The full pattern across all Phase 4 labs:

CloudTrail (Lab 4.1) - captures every API call

GuardDuty (Lab 4.2) - detects malicious API calls

Security Hub (Lab 4.3) - aggregates findings from all services

Config (this lab) - tracks compliance and enables remediation

EventBridge + Lambda (Lab 4.6) - executes remediation automatically

Together, these form the detect-and-respond stack. Each layer serves a specific purpose:

CloudTrail: audit

GuardDuty: threat detection

Security Hub: aggregation

Config: compliance

EventBridge + Lambda: response

No single service is sufficient. The value comes from the combination.

The Bottom Line
Config records every resource change with full configuration

Config rules evaluate compliance periodically (not real-time)

INSUFFICIENT_DATA is normal during initial evaluation

Auto-remediation via SSM Automation is the "self-healing" pattern

Config is the evidence trail for compliance audits

Config requires S3, IAM role, and bucket policy - all three mandatory

The S3 rule confirmed Block Public Access from Lab 3.2 is working

EBS default encryption from Lab 3.6 works automatically (volumes are auto-encrypted)

Config works hands-on in this account (unlike GuardDuty, Macie, Security Hub)
