# Lab 4.2 - GuardDuty - ML Threat Detection

**Date:** 2026-10-30
**Goal:** Understand GuardDuty, its data sources, and its finding structure. Design mode due to SCP block, but the response pipeline (EventBridge + SNS) was built and tested with simulated GuardDuty-format events.

## Objective

1. Understand what GuardDuty detects and how
2. Document the detector configuration for full protection
3. Understand the finding structure and severity model
4. Build the EventBridge rule that routes high-severity findings
5. Build the SNS topic for notifications
6. Test the pipeline with simulated findings
7. Document the AWS source protection that prevents spoofed events

## Concept: What GuardDuty Is

Amazon GuardDuty is a managed threat detection service. It continuously analyzes AWS data sources using machine learning, anomaly detection, and known threat intelligence to identify malicious activity.

GuardDuty does not require agents. It has direct API access to:

- CloudTrail management events (every API call)
- CloudTrail S3 data events (optional, high volume)
- VPC Flow Logs (network traffic metadata)
- DNS resolver logs (domain lookups)
- EKS audit logs (Kubernetes control plane)
- S3 protection (suspicious data access)
- EBS malware protection (volumes attached to suspicious instances)
- RDS login activity (authentication patterns)

The three always-on data sources are CloudTrail, VPC Flow, and DNS. Others are opt-in features that add detection coverage but also increase cost.

## Concept: Finding Types

GuardDuty findings have a type in the format `Category:Resource/Threat`.

### Common categories

- **Recon** - reconnaissance (port scanning, unusual API enumeration)
- **UnauthorizedAccess** - credential misuse
- **CryptoCurrency** - mining activity
- **Trojan** - malware communication
- **Backdoor** - persistent access
- **PenTest** - penetration testing activity (may be legitimate)
- **Stealth** - defense evasion
- **Policy** - policy violations (e.g., S3 public access)
- **Discovery** - attacker mapping the environment
- **Exfiltration** - data leaving the account

### Common finding types

| Finding | What it means |
|---|---|
| UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS | EC2 instance role credential used from outside AWS |
| UnauthorizedAccess:IAMUser/TorIPCaller | API call from a Tor exit node |
| CryptoCurrency:EC2/BitcoinTool.B!DNS | DNS query to a known crypto mining domain |
| Trojan:EC2/BlackholeTraffic | Traffic to a known command-and-control server |
| Recon:EC2/PortProbeUnprotectedPort | External port scan on a vulnerable port |
| Policy:S3/BucketPublicAccessGranted | A bucket was made public |
| Impact:EC2/AbusedDomainRequest.Reputation | DNS to a known malicious domain |

### Severity

Findings have a numeric severity from 0.1 to 10:

- **Low (1.0-3.9)** - informational, may be benign
- **Medium (4.0-6.9)** - suspicious, investigate when time permits
- **High (7.0-8.9)** - likely malicious, investigate promptly
- **Critical (9.0-10.0)** - active compromise, respond immediately

The `severity` field in the EventBridge event is a numeric value that the event pattern filters on.

### Finding structure

A full finding includes:
- `type` - the finding type string
- `severity` - numeric score
- `title` - human-readable summary
- `description` - detailed explanation
- `accountId`, `region`
- `resource` - what was affected (EC2 instance, IAM user, S3 bucket, etc.)
- `service` - metadata about the detection (action, source, additionalInfo)
- `createdAt`, `updatedAt` - timestamps
- `id` - unique finding ID

## The SCP Blocker

The GuardDuty API was rejected:
User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform:
guardduty:ListDetectors on resource:
arn:aws:guardduty:eu-north-1:803964124082:detector/* with an explicit deny in
a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

text

This is the same SCP (p-whl27g4i) that blocks Macie, Network Firewall, Access Analyzer, and IAM CreateGroup. The enterprise pattern: detection services are managed centrally by the organization.

## Design Artifacts

### 1. Detector configuration

File: policies/guardduty-detector.json

```json
{
  "Enable": true,
  "FindingPublishingFrequency": "FIFTEEN_MINUTES",
  "DataSources": {
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}}
  },
  "Features": [
    {"Name": "CLOUD_TRAIL", "Status": "ENABLED"},
    {"Name": "DNS_LOGS", "Status": "ENABLED"},
    {"Name": "FLOW_LOGS", "Status": "ENABLED"},
    {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
    {"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"},
    {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
    {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"}
  ]
}
All detection features enabled. In production, some may be disabled to reduce cost:

S3_DATA_EVENTS - very high volume for active data lakes, expensive

EBS_MALWARE_PROTECTION - charges per GB scanned when suspicious activity triggers a scan

EKS_AUDIT_LOGS - only relevant if EKS is used

2. High-severity finding filter
File: policies/high-severity-filter.json

json
{
  "Name": "HighSeverityCritical",
  "Description": "Publish only high-severity GuardDuty findings",
  "FindingCriteria": {
    "Criterion": {
      "severity": {"Gte": 7}
    }
  },
  "Action": "PUBLISH",
  "Rank": 1
}
Routes only findings with severity >= 7 to SNS/EventBridge. Lower-severity findings are still recorded (viewable in console) but not published for automated response.

The action: PUBLISH behavior means: if a finding matches this filter, publish it. If no filter matches, findings are not automatically published to EventBridge (they are still stored for console review).

3. Finding destination
File: policies/finding-destination.json

json
{
  "DetectionDestinationType": "SNS",
  "SnsTopicArn": "arn:aws:sns:eu-north-1:803964124082:lab42-guardduty-findings",
  "PublishingFrequency": "FIFTEEN_MINUTES"
}
Routes findings to an SNS topic. From SNS, you can fan out to:

Email (via email subscription)

SQS (for Lambda processing)

Lambda (direct invocation)

HTTP/HTTPS webhook (to a SIEM or ticketing system)

The Response Pipeline (Built and Tested)
Even though GuardDuty is blocked, the response infrastructure works:

SNS topic
Created: arn:aws:sns:eu-north-1:803964124082:lab42-guardduty-findings

Purpose: receives findings from GuardDuty (or simulated events) and fans out to subscribers.

EventBridge rule
Created: arn:aws:events:eu-north-1:803964124082:rule/lab42-high-severity-findings

Purpose: matches events from GuardDuty with severity >= 7, routes to SNS.

Event pattern (file: policies/guardduty-event-pattern.json):

json
{
  "source": ["aws.guardduty", "lab42.simulated.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{"numeric": [">=", 7]}]
  }
}
Note the second source - lab42.simulated.guardduty - was added to enable testing with custom events, because EventBridge blocks spoofing the aws.guardduty source.

Test result
Sending a simulated event:

aws events put-events --entries file://simulated-finding.json

Returned:

json
{
    "FailedEntryCount": 0,
    "Entries": [{"EventId": "dc70defd-a4a1-74ed-4415-3d9db9e13e21"}]
}
The event was accepted. The rule matched. The SNS target was notified.

The AWS Source Protection
What we tried first
Sending the event with "Source": "aws.guardduty":

Result:

json
{
    "FailedEntryCount": 1,
    "Entries": [{
        "ErrorCode": "NotAuthorizedForSourceException",
        "ErrorMessage": "Not authorized for the source."
    }]
}
What this means
EventBridge reserves certain source names for AWS services. You cannot publish an event with Source: aws.guardduty, Source: aws.cloudtrail, Source: aws.config, or any other AWS-managed source. This is a security feature.

If spoofing were allowed, an attacker with sufficient permissions could generate fake "GuardDuty findings" to trigger false alarms, wasting response team time, or (worse) injecting data into a SIEM to trigger automated containment actions against innocent resources.

The protection is enforced at the EventBridge API level. It cannot be bypassed by IAM permissions - the source name is reserved by the service.

The workaround for testing
Use a custom source prefix (lab42.simulated.guardduty). The rule pattern matches both sources. In production:

Real GuardDuty events use aws.guardduty

The custom source is removed from the pattern

Only real GuardDuty findings trigger the rule

The Full Integration Flow
In production (without SCP):

GuardDuty detects - analyzes CloudTrail, VPC Flow, DNS for threat patterns

GuardDuty publishes a finding - finding with severity, type, resource info

EventBridge rule matches - the rule filters on source=aws.guardduty and severity >= 7

SNS receives the event - topic delivers to all subscribers

Subscribers react - security team gets email, Lambda invokes for automated response, SIEM ingests for correlation

The response can be:

Notification only - email/Slack to the security team

Automated containment - Lambda terminates instance, revokes credentials, blocks IP

Ticketing - ServiceNow/Jira ticket created automatically

SIEM ingestion - Splunk/Elastic searches for correlation with other events

Cost Model
GuardDuty costs depend on data volume, not a flat fee:

Data source    Cost
CloudTrail management events    ~$4 per million events
VPC Flow Logs    ~$1 per GB analyzed
DNS Logs    ~$1 per million queries
S3 data events    ~$0.80 per million events
EKS audit logs    ~$1 per GB analyzed
EBS malware protection    ~$0.03 per GB scanned
RDS login events    ~$0.01 per 1000 events
For a typical small account, GuardDuty costs $20-100/month. For a large account with high volume, it can be $10,000+/month.

The cost optimization pattern:

Enable the three baseline sources (CloudTrail, VPC Flow, DNS) - these are the highest-value detections

Enable S3 data events only for specific sensitive buckets (via bucket-level GuardDuty S3 protection exclusions)

Consider disabling EBS malware protection if the cost per scan is high and the account rarely has suspicious EC2 activity

Lessons / Gotchas
GuardDuty does not require agents. It has direct API access to CloudTrail, VPC Flow, and DNS. No log configuration needed.

GuardDuty does not depend on your CloudTrail trail. Even without a trail, GuardDuty sees the same management events. The trail is for retention/audit; GuardDuty is for detection.

EventBridge blocks AWS-managed source spoofing. You cannot publish Source: aws.guardduty from your own code. This is intentional.

Finding severity is a numeric score, not a label. The event pattern must use numeric comparison, not string comparison.

The default finding publishing frequency is 6 hours. Setting it to 15 minutes gives faster notification but more EventBridge invocations (and cost). For high-severity findings, faster is worth it.

Automated response is powerful and dangerous. A Lambda that terminates instances on "GuardDuty severity >= 7" could terminate production workloads if the finding is a false positive. Best practice: notifications first, automated containment after the finding type and conditions are well understood.

GuardDuty is region-specific. Findings in eu-north-1 do not appear in us-east-1. For multi-region accounts, enable GuardDuty in every region OR use the org-wide delegation feature (management account enables it everywhere).

GuardDuty is a security service, not a compliance service. It finds threats. Compliance is Config/Security Hub. The two are complementary.

Malware protection (EBS scanning) is different from GuardDuty's core detection. It triggers only when suspicious activity is detected (e.g., a crypto mining finding). It is not a continuous scanner.

Findings are searchable for 90 days in the console. For long-term retention and correlation, export to S3 and query with Athena.

Files
policies/guardduty-detector.json - the full detector configuration (design mode)

policies/high-severity-filter.json - the finding filter (design mode)

policies/finding-destination.json - the notification configuration (design mode)

policies/guardduty-event-pattern.json - the EventBridge event pattern (deployed)

simulated-finding.json - the test event used to prove the pipeline

eventbridge-rules.json - the EventBridge rule state

sns-topics.json - the SNS topic state

sns-attributes.json - the SNS topic attributes

Cleanup
aws events remove-targets --rule lab42-high-severity-findings --ids 1
aws events delete-rule --name lab42-high-severity-findings
aws sns delete-topic --topic-arn arn:aws:sns:eu-north-1:803964124082:lab42-guardduty-findings

Real-World Application
The Security Operations Center (SOC) Workflow
GuardDuty is the primary signal source for most SOCs:

Triage - analyst reviews new findings by severity

Triage classification - false positive, benign true positive, or real threat

Investigation - for real threats, query CloudTrail for related activity

Containment - isolate affected resources, revoke compromised credentials

Eradication - remove threat actors, patch vulnerabilities

Recovery - restore normal operations

Post-incident review - update detection rules, improve response playbooks

The EventBridge + SNS pipeline is what feeds this workflow. Without it, SOCs would not know about threats in real time.

The Auto-Containment Pattern
The most aggressive response pattern:

GuardDuty fires UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS (severity 8.5)

EventBridge routes to Lambda

Lambda:

Looks up the affected EC2 instance

Removes all security group rules (network isolation)

Revokes temporary credentials via IAM

Tags the instance compromised: true

Creates a ServiceNow incident

Notifies the security team via Slack

The instance is isolated in seconds. The security team investigates without risk of further compromise.

This is what "shift-left security" and "SOAR" (Security Orchestration, Automation, and Response) look like in practice.

The Multi-Account Pattern
For an AWS Organization, GuardDuty is usually:

Enabled at the organization level (management account delegates)

Delegated to a security account for centralized administration

Findings aggregated via Security Hub in the security account

Members automatically enrolled (no per-account setup)

This is why the SCP blocks GuardDuty in member accounts - it's managed centrally, not per-account.

The False Positive Problem
GuardDuty is not perfect. Common false positives:

PenTest findings - the org's own red team running authorized tests

Recon findings - legitimate vulnerability scanners

CryptoCurrency findings - legitimate build pipelines using GPU instances

Best practice: filter known-good activity with finding filters (suppress) rather than disabling detection. A suppressed finding is still recorded but not surfaced - you have visibility if the pattern changes.

The Bottom Line
GuardDuty is the primary threat detection service in AWS

It uses machine learning on CloudTrail, VPC Flow, and DNS - no agents

Findings have types, severity, and resource details

EventBridge + SNS is the standard notification pipeline

Lambda is the standard automation layer

AWS source spoofing is blocked - the aws.guardduty source is reserved

Severity filters prevent alert fatigue - route only high findings automatically

GuardDuty is often managed centrally; member accounts cannot enable it

The response pipeline works even when GuardDuty is blocked - you tested it with simulated events
