# Lab 4.1 - CloudTrail - Every API Call, Forever

**Date:** 2026-10-30
**Goal:** Enable a proper CloudTrail trail with multi-region logging and S3 delivery, closing the audit gap identified in Lab 3.6. Learn to query trail logs for incident investigation.

## Objective

1. Verify the audit gap (no trail existed)
2. Create an S3 bucket with the CloudTrail bucket policy
3. Create a multi-region trail with log file validation
4. Start logging and verify delivery to S3
5. Decompress and inspect a trail log file
6. Query the trail for specific events
7. Add CloudWatch Logs integration with retention

## Concept: What CloudTrail Is

CloudTrail records every AWS API call made in your account. Every action - creating a bucket, reading a secret, assuming a role, changing a security group - is logged with:

- **Who** (userIdentity: IAM user, assumed role, AWS service)
- **What** (eventName)
- **When** (eventTime)
- **From where** (sourceIPAddress)
- **What was requested** (requestParameters)
- **What was returned** (responseElements)
- **Success or failure** (errorCode, if any)
- **TLS version and cipher** (tlsDetails)

## Concept: Trail vs Event History

There are two ways to see CloudTrail data:

### Event History (built-in, automatic)

- Available immediately, no setup required
- 90-day retention only
- Searchable via console and API (limited attributes)
- Free
- Cannot be exported

### Trail (you create it)

- Delivers to S3 (permanent retention) and optionally CloudWatch Logs (real-time query)
- Retained forever in S3
- Queryable with Athena, CloudWatch Logs Insights
- Configurable scope (single region, multi-region, all accounts)
- Log file integrity validation (SHA-256 digest files)

The trail is what you need for compliance. Event History is what you get for free.

## Concept: Trail Types

- **Single-region trail** - only logs events from the trail's home region
- **Multi-region trail** - logs events from all regions (recommended)
- **Organization trail** - logs events from all member accounts in the org (management account creates it)

A multi-region trail must be created in one region, but it captures events from every region. The trail's home region is where you manage it; the logs include all regions.

## Concept: Event Categories

- **Management events** - control plane operations (CreateBucket, RunInstances, IAM changes). Logged by default.
- **Data events** - data plane operations (S3 GetObject, Lambda Invoke). Optional, higher cost, high volume.
- **Insight events** - unusual API call patterns (excessive rate, error rate spikes). Optional.

Most security incidents involve management events (credential theft, permission changes, resource creation). Data events matter for detecting unauthorized data access (S3 GetObject by an unusual principal).

## What Was Built

| Resource | Value |
|---|---|
| Trail name | lab41-trail |
| Trail ARN | arn:aws:cloudtrail:eu-north-1:803964124082:trail/lab41-trail |
| S3 log bucket | lab41-cloudtrail-logs-803964124082-20261030075911 |
| Multi-region | true |
| Log file validation | true |
| Global service events | true |
| CloudWatch Logs group | /aws/cloudtrail/lab41-trail |
| CloudWatch retention | 30 days |
| Status | Logging |

## Setup Commands

### 1. Create the log bucket

$logBucket = "lab41-cloudtrail-logs-803964124082-$(Get-Date -Format 'yyyyMMddHHmmss')"
aws s3api create-bucket --bucket $logBucket --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1

### 2. Create the bucket policy

File: policies/cloudtrail-bucket-policy.json

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::BUCKET_NAME"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::BUCKET_NAME/AWSLogs/803964124082/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
Apply:

aws s3api put-bucket-policy --bucket $logBucket --policy file://policies/cloudtrail-bucket-policy.json

Both statements are required. CloudTrail needs s3:GetBucketAcl to verify the bucket and s3:PutObject to write. Missing either causes the trail to fail silently - logs are not delivered, and the only signal is in get-trail-status as a LatestDeliveryError.

3. Create the trail
aws cloudtrail create-trail --name lab41-trail --s3-bucket-name $logBucket --is-multi-region-trail --enable-log-file-validation

Returned:

Field    Value
Name    lab41-trail
S3BucketName    lab41-cloudtrail-logs-803964124082-20261030075911
IsMultiRegionTrail    true
LogFileValidationEnabled    true
IncludeGlobalServiceEvents    true
TrailARN    arn:aws:cloudtrail:eu-north-1:803964124082:trail/lab41-trail
4. Start logging
aws cloudtrail start-logging --name lab41-trail

Verify:

aws cloudtrail get-trail-status --name lab41-trail

Returned:

{
"IsLogging": true,
"LatestDeliveryTime": null,
"LatestDeliveryError": null
}

LatestDeliveryTime is null for the first ~5 minutes. This is normal. Once the first batch is delivered, LatestDeliveryTime is populated and LatestDeliveryError stays null.

5. Create CloudWatch Logs group
aws logs create-log-group --log-group-name /aws/cloudtrail/lab41-trail
aws logs put-retention-policy --log-group-name /aws/cloudtrail/lab41-trail --retention-in-days 30

Retention matters: CloudWatch Logs without retention never expires - it accrues cost forever. 30 days is a reasonable retention for real-time query; S3 is the permanent store.

Trail Log Delivery Verified
After ~5 minutes:

aws s3 ls "s3://$logBucket/AWSLogs/803964124082/" --recursive

Returned:

text
AWSLogs/803964124082/CloudTrail-Digest/
AWSLogs/803964124082/CloudTrail/eu-north-1/2026/10/30/803964124082_CloudTrail_eu-north-1_20261030T0510Z_xxx.json.gz
AWSLogs/803964124082/CloudTrail/us-east-1/2026/10/30/803964124082_CloudTrail_us-east-1_20261030T0505Z_yyy.json.gz
Three things to note:

The CloudTrail-Digest folder contains SHA-256 digest files for log integrity validation.

Logs from eu-north-1 appear even though the trail is managed in eu-north-1 - this is where most events originate.

Logs from us-east-1 appear because the trail is multi-region and us-east-1 is the global services region (IAM, STS, CloudFront events are recorded there).

Trail Log Structure
A trail log is a gzipped JSON file. The decompressed structure is:

json
{
    "Records": [
        {
            "eventVersion": "1.11",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDA...",
                "arn": "arn:aws:iam::803964124082:user/admin-zeff",
                "accountId": "803964124082",
                "accessKeyId": "AKIA...",
                "userName": "admin-zeff"
            },
            "eventTime": "2026-10-30T05:03:30Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "awsRegion": "eu-north-1",
            "sourceIPAddress": "41.90.64.19",
            "requestParameters": {"Host": "s3.eu-north-1.amazonaws.com"},
            "responseElements": null,
            "tlsDetails": {"tlsVersion": "TLSv1.3", ...},
            "eventType": "AwsApiCall",
            "managementEvent": true,
            "readOnly": true
        }
    ]
}
Trail Log Records from This Lab
Parsed view of the sample log file:

Time    Event    User    Source IP
05:03:30Z    ListBuckets    admin-zeff    41.90.64.19
05:03:43Z    DescribeTrails    (service)    resource-explorer-2.amazonaws.com
05:03:43Z    GetTrailStatus    (service)    resource-explorer-2.amazonaws.com
05:03:43Z    AssumeRole    (service)    resource-explorer-2.amazonaws.com
05:04:22Z    LookupEvents    admin-zeff    41.90.64.19
05:07:39Z    CreateLogGroup    admin-zeff    41.90.64.19
05:07:54Z    DescribeLogGroups    admin-zeff    41.90.64.19
What These Records Tell Us
admin-zeff with IP 41.90.64.19 made all the human calls. This IP is the only one recorded for the user, so any other IP for admin-zeff is anomalous and would trigger investigation.

resource-explorer-2.amazonaws.com made service-initiated calls (DescribeTrails, GetTrailStatus, AssumeRole). These are AWS internal services acting on your behalf. The invokedBy field identifies the service; the userIdentity.type is AWSService for these records.

The AssumeRole record includes the assumedRoleUser.arn and the credential accessKeyId (starting with ASIA). The sessionToken in the response is partially redacted by CloudTrail (long tokens are truncated for display); the actual credential values are present in the requestID audit chain.

Querying the Trail
Event History lookup (recent events)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=CreateTrail

Returns events from the last 90 days, even those not yet in a trail. This works immediately.

S3 trail lookup (permanent, requires Athena)
To query the trail logs in S3, use Amazon Athena with the CloudTrail table. Setup:

Create an Athena database and table pointing at the trail's S3 location

Query with SQL: SELECT eventname, useridentity.username, sourceipaddress FROM cloudtrail WHERE eventtime > '2026-10-30'

The Athena setup is more work than this lab, but it is the standard way to query trail logs historically.

Time-range lookup (needs UTC)
The most common pitfall in this lab: time zones.

CloudTrail uses UTC. PowerShell Get-Date returns local time. Always convert:

powershell
$startTime = (Get-Date).ToUniversalTime().AddHours(-2).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

aws cloudtrail lookup-events `
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateTrail `
  --start-time $startTime --end-time $endTime
Without .ToUniversalTime(), the CLI rejects the range with InvalidTimeRangeException: The start time precedes the end time. The suffix "Z" means UTC, but PowerShell sends local-time values with a "Z" suffix, which AWS interprets as future UTC times.

Log File Integrity Validation
When enabled (--enable-log-file-validation), CloudTrail writes a SHA-256 digest file for each log file. The digest is signed with a KMS key and stored in the CloudTrail-Digest folder.

To validate:

aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:eu-north-1:803964124082:trail/lab41-trail --start-time $startTime

Validation confirms the log files have not been tampered with or deleted. This is required by compliance frameworks that demand audit integrity (PCI, HIPAA, SOC 2).

Lessons / Gotchas
Both bucket policy statements are required. CloudTrail silently fails to deliver logs if either is missing. The failure is visible only in get-trail-status as LatestDeliveryError, not at trail creation time.

The first delivery takes ~5 minutes. LatestDeliveryTime is null until the first batch. This is expected, not an error.

Timezone confusion is common. AWS APIs use UTC. Convert PowerShell local time with .ToUniversalTime() before formatting for --start-time and --end-time.

Multi-region trails capture all regions from one home region. The --is-multi-region-trail flag means a single trail in eu-north-1 logs events from us-east-1, eu-west-1, ap-south-1, and so on.

Management events are free; data events are not. Default CloudTrail captures management events. Data events (S3 GetObject, Lambda Invoke) cost extra and generate high volume. Enable selectively for sensitive resources.

Event History is separate from the trail. Both exist independently. Event History is 90-day retention via console/API. Trail is permanent via S3. Neither affects the other.

CloudWatch Logs retention is mandatory for cost control. Log groups without retention grow forever. Set retention explicitly.

Organization trails are the standard for multi-account. In an AWS Organization, a single organization trail in the management account captures every API call from every member account. This is what auditors expect to see.

The trail S3 bucket should be in a dedicated log account. Best practice is to route all CloudTrail logs to a centralized logging account with restricted access. Member accounts cannot delete their own audit trail.

CloudTrail logs the access key ID, not the secret. In the AssumeRole response, the accessKeyId (ASIA...) is logged, but the secretAccessKey is not. The sessionToken is partially redacted. The log shows what was given, not the actual credentials.

Activity IS logged immediately, even without a trail. The 90-day Event History captures every API call regardless of trail configuration. A trail extends retention to forever (via S3); it does not change what is logged.

Access to the log bucket must be locked down. If an attacker can delete logs from S3, the trail is useless. Best practice: bucket policy allows CloudTrail to write, denies all delete operations, and enables Object Lock or MFA delete.

Files
policies/cloudtrail-bucket-policy.json - the CloudTrail bucket permission policy

trail-config.json - the trail configuration

trail-status.json - the trail status after start

event-history-sample.json - 20 events from the Event History

trail-sample.json - decompressed sample trail log

Cleanup
aws cloudtrail stop-logging --name lab41-trail
aws cloudtrail delete-trail --name lab41-trail
aws logs delete-log-group --log-group-name /aws/cloudtrail/lab41-trail
aws s3 rm "s3://
l
o
g
B
u
c
k
e
t
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
logBucket"−−recursiveawss3apidelete−bucket−−bucketlogBucket

Important: Do NOT stop the trail in production. The trail is the audit log. Stopping it means losing compliance evidence.

Real-World Application
The Compliance Baseline
PCI DSS, HIPAA, SOC 2, and FedRAMP all require API audit logging. CloudTrail is the AWS service that satisfies this requirement. An organization without a trail in every region cannot pass audit.

The specific requirements:

Trail enabled in all regions

Log delivery to S3 verified (not just configured)

Log file integrity validation enabled

Retention meets regulatory period (typically 1-7 years)

Access to logs restricted (logs must not be modifiable)

The Incident Investigation Pattern
When a security incident occurs:

Determine the scope. Which IAM user, role, or service was involved? Query CloudTrail for that principal's activity in the hours before and after the incident.

Determine the timeline. Sort events by timestamp. Identify the first unauthorized action.

Determine the source. What IP address did the action come from? Is it a known corporate IP or an unfamiliar one?

Determine the access. Did the attacker use a valid credential or assume a role? Query for AssumeRole events around the incident time.

Determine the impact. What resources were touched? Query for specific event names (CreateBucket, RunInstances, PutBucketPolicy, etc.) for the involved principal.

This is what SOC analysts do daily. A good CloudTrail setup makes investigation possible in minutes rather than days.

The Detection Engineering Pattern
CloudTrail is also the source for automated detection:

EventBridge rules trigger on specific event patterns (e.g., "CreateTrail disabled" or "PublicAccessBlock removed")

GuardDuty consumes CloudTrail to detect threats (unusual API calls, compromised credentials)

Custom Lambda functions process CloudTrail logs to detect anomalies not covered by AWS-managed services

The Data Event Economics
For most accounts, management events are sufficient. Data events (S3 GetObject on a bucket) are expensive at volume - a busy data lake can generate millions of events per day.

The pattern:

Enable data events only for specific buckets (e.g., customer PII buckets, financial data)

Use CloudTrail Lake for querying high volumes without copying to S3

Retain data events for a shorter period (30-90 days) than management events (years)

Enable advanced event selectors to filter out high-noise events

The Bottom Line
CloudTrail is mandatory. No exceptions for any regulated workload.

Multi-region trail with S3 delivery and log validation is the baseline.

CloudWatch Logs adds real-time query; S3 adds permanent retention.

Event History (90 days) is free and always available.

Trail logs are the audit foundation for every security investigation.

The bucket policy is the #1 gotcha. Both statements are required.

Time zones are the #2 gotcha. Always convert to UTC.

The audit gap identified in Lab 3.6 is now closed. Every API call in this account is logged permanently to S3.
