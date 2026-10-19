# Lab 3.7 - Amazon Macie - Sensitive Data Discovery

**Date:** 2026-10-19
**Goal:** Understand how Amazon Macie discovers sensitive data in S3, what kinds of data it can find, how findings are structured, and how to integrate Macie into a security workflow. Adapted to design mode after the Macie APIs were found to be SCP-blocked in this account.

## Objective

1. Understand what Macie is and the problems it solves
2. Learn the two discovery modes (automated vs targeted)
3. Understand the finding structure (severity, category, location)
4. Design custom data identifiers for organization-specific patterns
5. Design finding filters for alert routing
6. Design the Macie session configuration
7. Document the full deployment pattern for accounts where Macie is available

## Concept: What Macie Is

Amazon Macie is a fully managed data security service that uses machine learning and pattern matching to discover, classify, and protect sensitive data stored in S3.

Its three primary functions:

1. **Discover** - scan S3 buckets for sensitive data patterns
2. **Classify** - categorize findings by type (PII, financial, credentials, health)
3. **Monitor** - evaluate bucket security posture (encryption, public access, sharing)

The problem it solves: In an S3-heavy AWS environment, there are often millions of objects across dozens of buckets. Some of them contain sensitive data the organization may not know about. Manual review is impossible. Macie automates the discovery.

## Concept: Two Discovery Modes

### Automated Discovery

- Runs continuously on all buckets in scope
- Uses AWS-managed data identifiers (built-in patterns for SSNs, credit cards, etc.)
- Evaluates bucket security posture on every scan
- Cost: charged per GB scanned plus per bucket monitored

Best for: baseline visibility across the entire account.

### Targeted Discovery Jobs

- Runs on a schedule or once
- You choose specific buckets, specific data identifiers
- Can include custom identifiers (organization-specific patterns)
- Can control scan depth (sampling vs full object scan)
- Cost: higher per-GB rate than automated

Best for: focused investigation, compliance audits, high-value data protection.

## Concept: AWS-Managed Data Identifiers

Macie ships with hundreds of managed identifiers organized into categories:

### PERSONAL_INFORMATION (PII)
- Name, address, phone number
- Date of birth
- Passport number
- Driver license number
- National ID number (country-specific)
- Social Security Number

### FINANCIAL_INFORMATION
- Credit card numbers (all major brands)
- Bank account numbers
- IBAN
- SWIFT codes
- Tax IDs

### CREDENTIALS
- AWS access keys (AKIA prefix)
- AWS secret keys
- API keys (Stripe, GitHub, Slack, etc.)
- Private keys (PEM, PKCS)
- Passwords in connection strings

### HEALTH_INFORMATION
- Medical record numbers
- Insurance IDs
- Prescription data

### CUSTOM
- Your own regex patterns
- Organization-specific identifiers

The complete list is in the AWS docs under "Managed data identifiers for Macie".

## Concept: Findings

A Macie finding is a structured report of a scan result. Key fields:

- **severity** - LOW, MEDIUM, HIGH
- **category** - PERSONAL_INFORMATION, FINANCIAL, CREDENTIALS, etc.
- **type** - specific identifier (e.g., "USA_SOCIAL_SECURITY_NUMBER")
- **location** - bucket, object key, byte offset, line number
- **sample** - redacted sample of the matched data
- **sensitiveData** - array of all detected types in the object

A single object with mixed sensitive data produces one finding with multiple types.

### Sample finding

```json
{
    "severity": {"description": "High"},
    "category": "PERSONAL_INFORMATION",
    "type": "USA_SOCIAL_SECURITY_NUMBER",
    "location": {
        "s3Object": {
            "bucketName": "customer-data",
            "key": "exports/2026/customers.csv",
            "path": "customers.csv"
        },
        "lineStart": 1,
        "lineRange": 42
    },
    "sensitiveData": [
        {
            "category": "PERSONAL_INFORMATION",
            "type": "USA_SOCIAL_SECURITY_NUMBER",
            "count": 42
        }
    ]
}
The finding tells you exactly where the SSNs are (line 42 of customers.csv) and how many (42).

Concept: Bucket Security Posture
Beyond data discovery, Macie continuously evaluates bucket security:

Encryption at rest enabled?

Public access blocked?

Shared with other accounts?

Versioning enabled?

CloudTrail logging enabled?

These are reported as findings of category POLICY or CONFIGURATION. This is similar to Security Hub's S3 checks, but integrated with data discovery findings.

The SCP Blocker
The Macie session API was rejected:

text
User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform:
macie2:GetMacieSession on resource:
arn:aws:macie2:eu-north-1:803964124082:* with an explicit deny in a service
control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i
This is the same SCP (p-whl27g4i) that blocks GuardDuty, Access Analyzer, Network Firewall, and IAM CreateGroup. The pattern: detection and data security services are blocked at the organization level, likely because the organization prefers centralized detection (GuardDuty, Security Hub, Macie administered from the management account).

This is a common enterprise design: member accounts cannot enable detection services because the org admin controls them centrally.

Design Artifacts
1. Custom data identifier
File: policies/custom-data-identifier.json

json
{
  "Name": "Lab37-EmployeeID",
  "Description": "Matches employee IDs in format EMP-XXXXXX",
  "Regex": "EMP-[0-9]{6}"
}
Custom identifiers let you find organization-specific patterns. Here, "EMP-123456" would be detected - a company-internal employee ID format that AWS does not know about.

To use this in a discovery job:

aws macie2 create-custom-data-identifier --cli-input-json file://policies/custom-data-identifier.json

Returns an ID that can be referenced in the discovery job configuration.

2. Finding filter
File: policies/high-severity-pii-filter.json

json
{
  "name": "HighSeverityPII",
  "description": "Show all high-severity PII findings",
  "action": "PUBLISH",
  "findingCriteria": {
    "criterion": {
      "severity.description": {
        "eq": ["High"]
      },
      "category": {
        "eq": ["PERSONAL_INFORMATION"]
      }
    }
  }
}
Finding filters route findings to specific destinations (SNS topics, EventBridge, etc.). This one publishes only high-severity PII findings - other findings are still recorded but not published.

The criterion can combine multiple attributes:

severity (LOW/MEDIUM/HIGH)

category (PERSONAL_INFORMATION/FINANCIAL/CREDENTIALS/HEALTH/POLICY)

type (specific identifier)

bucketName

accountId

region

sample text pattern

3. Macie session configuration
File: policies/macie-session-config.json

json
{
  "status": "ENABLED",
  "findingPublishingFrequency": "FIFTEEN_MINUTES",
  "autoEnable": false,
  "s3Destination": {
    "bucketName": "REPLACE-WITH-LOG-BUCKET",
    "keyPrefix": "macie-findings/"
  }
}
The session configuration controls:

status - ENABLED or PAUSED

findingPublishingFrequency - how often to send finding notifications (FIFTEEN_MINUTES / ONE_HOUR / SIX_HOURS)

autoEnable - whether to automatically enable in newly added AWS accounts (org-wide)

s3Destination - where findings are exported for long-term retention

The Full Deployment Pattern (For Accounts Where Macie Works)
Step 1 - Enable Macie
aws macie2 enable-macie

This creates the Macie session and starts monitoring. Costs begin immediately (~$0.10/bucket/month).

Step 2 - Configure the session
aws macie2 update-macie-session
--finding-publishing-frequency FIFTEEN_MINUTES
--status ENABLED

Step 3 - Create custom identifiers (optional)
aws macie2 create-custom-data-identifier
--name "EmployeeID"
--regex "EMP-[0-9]{6}"

Step 4 - Configure S3 destination for findings
aws macie2 put-findings-publication-configuration
--s3-destination "{"bucketName":"log-bucket","keyPrefix":"macie/"}"

Step 5 - Set up SNS notification for findings
Create an SNS topic

Add topic ARN to the session configuration

Subscribe recipients (email, SQS, Lambda)

Step 6 - Create a targeted discovery job
aws macie2 create-classification-job
--job-type ONE_TIME
--name "CustomerDataScan"
--s3-job-definition "{"bucketDefinitions":[{"accountId":"803964124082","buckets":["customer-data"]}]}"
--managed-data-identifier-ids "USA_SOCIAL_SECURITY_NUMBER"
--custom-data-identifiers "EmployeeID"

Wait for the job to complete. Findings appear in the console and are sent via SNS.

Step 7 - Review findings
aws macie2 list-findings --finding-criteria "{"criterion":{"severity.description":{"eq":["High"]}}}"

Step 8 - Integrate with Security Hub
aws securityhub batch-enable-standards --standards-subscription-requests "{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}"

Macie findings are automatically sent to Security Hub if both services are enabled. They appear as Macie findings alongside GuardDuty, Inspector, and Security Hub's own findings.

Integration with Other AWS Services
Security Hub
Macie findings are aggregated into Security Hub. A single Security Hub dashboard shows findings from all detection services - GuardDuty, Inspector, Macie, Config, IAM Access Analyzer, and Firewall Manager.

EventBridge
Macie publishes events to EventBridge. Rules can trigger Lambda for automated remediation:

text
Event: "Macie Finding"
Rule: IF finding.category = PERSONAL_INFORMATION AND finding.severity = HIGH
Then: INVOKE Lambda "quarantine-bucket"
CloudWatch Logs
Macie findings can be routed to CloudWatch Logs for retention beyond the 90-day console retention. Queries via Logs Insights can find patterns.

S3 export
Findings can be exported to S3 for long-term retention. The S3 export includes full finding JSON.

Cost Model
Automated Discovery
$0.10 per GB of data in monitored S3 buckets per month

$0.10 per bucket per month (minimum $0.10)

For a 1 TB bucket: ~$100/month.

Targeted Discovery Jobs
$1.00 per GB scanned (higher than automated)

For a 10 GB targeted scan: $10 (one-time).

Sensitive Data Finding Evaluation
Included in automated/targeted costs

Free Tier
Macie does not have a free tier. Any usage incurs charges.

Cost optimization
Use automated discovery for broad visibility

Use targeted discovery only for high-value data

Exclude known-safe buckets from automated discovery

Scope jobs to specific prefixes (e.g., only /exports/, not entire bucket)

Lessons / Gotchas
Macie is SCP-blocked in this account. Detection services are controlled at the org level - the management account enables and manages Macie for all member accounts. This is intentional enterprise governance.

Macie does not scan the whole bucket by default. Targeted jobs scan specific objects or prefixes. For a 10 TB bucket, you scan the subset you care about.

Sample data is redacted. Findings show the pattern and location but not the raw values. This is intentional - the finding itself must not leak sensitive data.

The 90-day console retention. Findings are visible in the console for 90 days. For longer retention, export to S3 or CloudWatch Logs.

Custom data identifiers have regex limits. Complex regexes can slow scans dramatically. Simple patterns (character classes, fixed-length identifiers) scan fast. Avoid unbounded quantifiers and backtracking.

Macie is region-specific. Findings in eu-north-1 do not appear in us-east-1. For multi-region organizations, either enable Macie in every region or centralize via Security Hub.

Macie scans S3 only. It does not scan EBS, RDS, DynamoDB, or other data stores. For those, use different tools (GuardDuty for detection, Config for compliance).

High cost at scale. A 100 TB S3 footprint could cost $10,000/month in Macie alone. Cost optimization is essential for large organizations.

The finding category is not the same as the severity. A single SSN in a test bucket is HIGH severity but low business impact. Review findings in context.

Macie findings can be remediated automatically via EventBridge + Lambda. Common patterns: tag the bucket "requires-review", revoke public access, move to quarantine, notify the data owner.

Real-World Application
The Regulatory Driver
Most Macie adoption is driven by compliance:

PCI DSS - Macie finds unencrypted credit cards, demonstrating control

HIPAA - Macie finds PHI, enabling remediation

GDPR - Macie finds EU PII, supporting data mapping exercises

CCPA - Macie finds California residents' data

The compliance framework requires "knowing where your data is." Macie answers that question at S3 scale.

The Data Classification Program
A common enterprise pattern:

Phase 1 - Enable Macie in automated mode on all buckets. Get a baseline of what's in S3.

Phase 2 - Review findings. Categorize buckets by sensitivity (public, internal, confidential, restricted).

Phase 3 - Add bucket-level tags reflecting sensitivity. Configure different controls per tier.

Phase 4 - Implement a data classification program. Every new bucket must be tagged with sensitivity level at creation.

Phase 5 - Continuous monitoring. Macie findings feed Security Hub. Changes in bucket sensitivity trigger review.

This is a 6-12 month program for a large organization.

The GDPR Data Mapping Pattern
When a data subject requests their data under GDPR:

Query Macie findings for the customer's email address (if it's in the data)

Get a list of S3 objects containing the address

Export those objects

Provide to the customer

Delete from S3 (and any other data stores)

Macie is not a search engine - it does not index data at this granularity. But for known patterns (SSNs, credit cards), the findings provide a searchable index. For arbitrary text (email addresses, names), a targeted scan is the right tool.

The Insider Threat Pattern
An employee tries to exfiltrate customer data:

Employee copies customer data to an S3 bucket they control

Macie detects PII in the new bucket location

EventBridge triggers on the "PublicBucket" or "SensitiveData" finding

Automated Lambda quarantines the bucket (removes public access, notifies security)

GuardDuty detects the anomalous API call pattern

Security Hub aggregates the multi-service findings for the SOC

This is the "defense in depth" story for cloud data security - multiple services producing correlated findings.

What Could Not Be Demonstrated
Because Macie is SCP-blocked in this account, the following operations could not be performed:

Enabling Macie session

Creating custom data identifiers

Running discovery jobs

Viewing findings

Configuring SNS notifications

Integrating with Security Hub

All configuration artifacts (custom identifier JSON, filter JSON, session config JSON) are written as reproducible files. They can be applied in any account where Macie is enabled by the organization.

Files
policies/custom-data-identifier.json - organization-specific pattern matcher

policies/high-severity-pii-filter.json - finding filter for alert routing

policies/macie-session-config.json - session configuration template

Real-World Application
The Managed Detection Stack
Macie is one of three detection services that work together:

GuardDuty - threat detection (malicious API calls, compromised credentials, crypto mining)

Macie - data discovery (PII in wrong places, unprotected sensitive data)

Inspector - vulnerability detection (outdated packages, exposed ports)

Together they cover the three main data security questions:

Is someone attacking us? (GuardDuty)

Where is our sensitive data? (Macie)

Are our resources vulnerable? (Inspector)

All three feed Security Hub. All three are typically enabled at the organization level.

The Centralized Management Pattern
For an organization with 100 member accounts, the typical setup:

Management account enables GuardDuty, Macie, Inspector

Admin delegates to a security account

Security account configures org-wide settings

All member accounts inherit the configuration

Findings flow to the security account's Security Hub

SOC operates from a single pane of glass

The SCPs in this account enforce this pattern - member accounts cannot enable Macie or change its configuration. This is not a limitation; it is governance.

The Cost of Detection at Scale
For an organization with 10 TB of S3 data:

Macie automated discovery: ~$1,000/month

Storage scanning of new objects: ~$0.10/GB

Targeted scans (quarterly): ~$10,000/year

Total detection cost: ~$22,000/year.

This is expensive but justifiable for organizations with regulatory requirements. For smaller organizations, targeted scans on specific buckets are the standard approach.

The Integration with Data Governance
Macie is one piece of a data governance program:

Data inventory - what data exists (Macie)

Data classification - what sensitivity level (tags + manual review)

Access control - who can access what (IAM + bucket policies)

Encryption - is data protected at rest (Macie + Config)

Monitoring - who is accessing data (CloudTrail + Macie)

Retention - how long data is kept (S3 lifecycle + Object Lock)

Macie contributes to items 1, 2, 4, and 5. The other items require complementary tools and processes.

The Bottom Line
Macie is the standard AWS tool for sensitive data discovery in S3

Automated + targeted discovery modes cover different use cases

Custom identifiers allow organization-specific patterns

Findings integrate with Security Hub, EventBridge, SNS, and CloudWatch

Cost scales with data volume - scope carefully

Detection services are often managed centrally at the org level - member accounts inherit them

This lab was design-mode because of SCP, but the patterns are complete and reproducible in an unblocked account
