# Lab 4.5 - Amazon Detective - Investigation and Root Cause Analysis

**Date:** 2026-10-31
**Goal:** Understand Amazon Detective, its behavior graph, and the investigation workflow used by security operations center (SOC) analysts. Design mode due to SCP block, but the investigation playbooks are documented in full detail as ready-to-use reference.

## Objective

1. Understand what Detective is and how it differs from GuardDuty
2. Learn the behavior graph concept and the entity model
3. Understand how Detective consumes GuardDuty findings
4. Document the three primary investigation playbooks
5. Design the behavior graph configuration
6. Document the SOC investigation workflow

## Concept: What Amazon Detective Is

Amazon Detective is an investigation service that helps analysts understand the root cause of security findings. It uses machine learning and statistical analysis to build a behavior graph of activity across IAM users and roles, EC2 instances, VPCs, subnets, security groups, IP addresses, and AWS accounts.

Detective does not detect threats itself. It investigates threats detected by other services (primarily GuardDuty). It answers the "why" and "how" questions after a finding has fired.

## Concept: The Difference from GuardDuty

| Aspect | GuardDuty | Detective |
|---|---|---|
| Purpose | Detect threats | Investigate threats |
| Output | Findings | Behavior graph + entity profiles |
| What it answers | "Something is wrong" | "What exactly happened and why?" |
| Triggered by | Continuous analysis | Analyst investigation |
| Data sources | CloudTrail, VPC Flow, DNS | CloudTrail, VPC Flow (no DNS) |
| Depends on | Nothing | GuardDuty findings (for starting point) |
| Cost | Per GB analyzed | Per GB ingested into behavior graph |

The two are complementary. GuardDuty says "there was an unauthorized API call from a Tor exit node." Detective shows "the same IAM role also made these 47 other API calls from 3 different IPs, accessed 2 S3 buckets, and had a session established from this EC2 instance."

## Concept: The Behavior Graph

The behavior graph is Detective's core data structure. It links entities and events.

### Entities

- AWS accounts - the account where activity occurred
- IAM users - named users who made API calls
- IAM roles - assumed roles (including service roles)
- EC2 instances - running instances that made network connections
- IP addresses - source IPs for API calls and network connections
- VPCs and subnets - network context for instances
- Security groups - network policy context

### Events

- API calls - every CloudTrail event, linked to the entity that made it
- Network connections - every VPC Flow record, linked to source and destination IPs
- Findings - every GuardDuty finding, linked to affected entities

### Edges

The graph links entities to events to other entities. Example:
IAM Role: app-role
-> made API call: s3:GetObject (5,000 times in 1 hour)
-> on bucket: customer-data
-> made API call: sts:AssumeRole
-> into role: admin-role (unusual)
-> from IP: 203.0.113.5 (Tor exit node)
-> from EC2 instance: i-abc123
-> in VPC: vpc-prod
-> with security group: sg-open-to-internet

text

An analyst can traverse these connections to understand the full scope of an incident.

## Concept: The Investigation Timeline

When GuardDuty fires a finding, Detective provides:

1. The finding - what GuardDuty detected
2. The entity - which IAM user, role, or instance is involved
3. The baseline - what that entity normally does (from historical data)
4. The deviation - what happened that was unusual
5. The connections - what other entities are linked to this activity
6. The timeline - when each event occurred, in chronological order

This is the "reconstruct the incident" view that analysts need.

## The SCP Blocker

The Detective API was rejected:
User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform:
detective:ListGraphs on resource: * with an explicit deny in a service control
policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

text

This is the seventh service blocked by p-whl27g4i:

1. IAM CreateGroup
2. GuardDuty
3. Macie
4. Access Analyzer (management)
5. Network Firewall
6. Security Hub
7. Detective

The org blocks all detection, data security, investigation, and aggregation services. These are managed centrally at the management account.

## Design Artifacts

### 1. Behavior graph configuration

File: policies/behavior-graph-config.json

```json
{
  "GraphName": "lab45-behavior-graph",
  "Tags": [
    {"Key": "Environment", "Value": "lab"},
    {"Key": "Purpose", "Value": "security-investigation"}
  ]
}
To create (in an unblocked account):

aws detective create-graph --cli-input-json file://policies/behavior-graph-config.json

Returns a GraphArn like arn:aws:detective:eu-north-1:803964124082:graph:lab45-behavior-graph. The graph takes 2-4 hours to populate before investigation is useful.

2. Member account configuration
File: policies/member-account-config.json

json
{
  "AccountId": "803964124082",
  "GraphArn": "arn:aws:detective:eu-north-1:803964124082:graph:lab45-behavior-graph"
}
For organizations, the management account creates the behavior graph. Member accounts are invited (or auto-enrolled via Organizations integration) to add their data to the graph.

3. Investigation playbooks
File: policies/investigation-patterns.json

Three playbooks document the standard investigation workflows:

CompromisedInstanceInvestigation - EC2 instance suspected of compromise

CompromisedCredentialInvestigation - IAM credential suspected of theft

CryptominingInvestigation - instance suspected of crypto mining

Each playbook has a starting point (where to look first) and a series of queries that lead to root cause.

Investigation Playbook 1: Compromised EC2 Instance
Trigger: GuardDuty finding UnauthorizedAccess:EC2/SSHBruteForce or CryptoCurrency:EC2/BitcoinTool.B

Starting point
The GuardDuty finding itself. It identifies the instance ID, the IP address involved, and the activity type.

Investigation steps in Detective
View the instance profile

Instance ID, launch time, instance type

VPC, subnet, security group

IAM instance profile attached

Tags (does it have sensitive data tags?)

Review the instance's recent API calls

Filter CloudTrail events by userIdentity.arn matching the instance role

Look for unusual calls: iam:CreateUser, s3:PutBucketPolicy, ec2:RunInstances

Check for calls to other regions (cross-region activity from a single instance is suspicious)

Review the instance's recent network connections

Filter VPC Flow events for the instance's ENI

Look for connections to known-bad IPs (Detective has threat intel integration)

Look for port scans from the instance (outbound reconnaissance)

Look for connections to unusual destinations (non-AWS IPs, foreign countries)

Trace the session

How did the attacker gain access?

If via SSH: what IP connected to port 22? (Check VPC Flow)

If via web app: what HTTP requests preceded the compromise? (Check ALB logs if available)

If via metadata service: what process queried 169.254.169.254? (Not visible in CloudTrail)

Identify lateral movement

What other resources did the instance's role access?

Did it attempt to reach RDS instances? Other EC2 instances? S3?

Did it assume other roles (cross-account pivot)?

Establish blast radius

What data was accessed by this instance's role?

What changes were made to the account (CreateUser, CreateRole, etc.)?

What other AWS accounts were contacted (cross-account API calls)?

Response actions
Based on findings:

Isolate the instance (remove all security group rules)

Revoke the instance role's temporary credentials (they expire in 1 hour, but if still active)

Block the source IP at the VPC NACL or Network Firewall

Rotate any secrets the instance had access to

Review all IAM policies attached to the instance role

Investigation Playbook 2: Leaked IAM Credential
Trigger: GuardDuty finding UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS or UnauthorizedAccess:IAMUser/TorIPCaller

Starting point
The finding identifies the IAM user or role, the IP address of the suspicious call, and the API call that triggered detection.

Investigation steps in Detective
View the credential's baseline behavior

What is the normal source IP for this user/role?

What is the normal set of API calls?

What is the normal set of accessed resources?

What is the normal time of day for activity?

Review the suspicious session

All API calls from the suspicious IP

All API calls with the suspicious session ID

What was the first anomalous call? (The initial access)

What was the full sequence of calls?

Check for privilege escalation

Did the suspicious session call iam:CreatePolicy or iam:AttachUserPolicy?

Did it call sts:AssumeRole to jump to another role?

Did it call iam:CreateAccessKey (creating a new long-lived key for persistence)?

Trace data access

Did the suspicious session call s3:GetObject? On which buckets?

Did it call dynamodb:Scan or rds:DescribeDBInstances?

Did it call secretsmanager:GetSecretValue or ssm:GetParameter?

Identify the persistence mechanism

Did the attacker create a new IAM user?

Did they add a new access key to an existing user?

Did they modify the trust policy of an IAM role?

Did they add an SSH key to an EC2 instance via EC2 Instance Connect?

Assess exfiltration

How much data was accessed? (CloudTrail doesn't show bytes, but API call volume is a proxy)

Where did the data go? (Outbound data transfer metrics)

Is any data still being accessed? (Ongoing activity from the same IP)

Response actions
Immediately: Revoke the leaked credential (delete the access key or force role session termination)

Contain: Remove any IAM changes made by the attacker (delete new users, keys, policies)

Eradicate: Identify how the credential was leaked (phishing, exposed in code, leaked in a public repo)

Recover: Rotate all secrets the credential had access to

Learn: Add detection rules for the pattern (unusual IP for this user)

Investigation Playbook 3: Cryptomining
Trigger: GuardDuty finding CryptoCurrency:EC2/BitcoinTool.B!DNS or CryptoCurrency:EC2/BitcoinTool.B

Starting point
The finding identifies the instance ID and the DNS query or network connection that triggered detection.

Investigation steps in Detective
View the instance lifecycle

When was the instance launched?

Who launched it? (IAM user or role from CloudTrail)

What instance type? (GPU instances are more likely to be targeted for mining)

What launch template or AMI was used?

Review the instance's network behavior

DNS queries to mining pool domains (Detective shows these)

Outbound connections to non-AWS IPs on unusual ports

High outbound data volume (mining doesn't require this, but exfiltration does)

Connections to known mining pools (Detective threat intel)

Trace the attack vector

Was the instance compromised via a vulnerability in the app?

Was it launched by a compromised IAM credential? (Check the launch API call)

Was it launched via a misconfigured launch template?

Was it compromised via SSRF from a web app?

Check for lateral movement

Did the miner try to spread to other instances?

Did it attempt to access IAM, S3, RDS?

Did it use the instance role for other activity?

Establish cost impact

When did the instance launch? (How long has it been running?)

What is the instance type? (GPU instances cost $1-30/hour)

What is the estimated cost of the mining activity?

What other resources were impacted? (Data transfer costs, EBS costs)

Response actions
Terminate the instance (not just stop - a stopped instance can be restarted)

Block the source IP if the attacker can launch again

Rotate the IAM credential that launched the instance (if it was compromised)

Review the account's EC2 launch policies (SCPs can restrict instance types)

Alert the billing team (mining can cost thousands before detection)

Concept: The Behavior Graph Queries
Detective's investigation is built around queries. Common query patterns:

Find all API calls from an IP
In Detective console: click on IP -> view all API calls from that IP

This shows if an IP is used by multiple principals (suspicious) or just one (possibly normal).

Find all API calls made by a role
Click on role -> view API calls

Compare current activity to baseline. Unusual calls (never seen before, or seen rarely) are suspicious.

Find all instances affected by a role's credentials
Click on role -> view instances that assumed the role

If the role credential was leaked, all instances using it are at risk.

Find the blast radius of an incident
Start with the affected entity -> traverse all connected entities

This identifies all resources that may need cleanup.

Integration with the Investigation Workflow
The SOC workflow
Alert - GuardDuty fires, Security Hub aggregates

Triage - analyst opens Security Hub finding

Investigation - analyst opens Detective from the Security Hub finding

Scope - analyst uses Detective to identify affected entities

Response - analyst takes containment actions

Eradication - analyst removes the threat

Recovery - analyst restores normal operation

Post-incident - analyst writes up findings

Detective is the tool for steps 3-4. The rest requires other tools (Lambda for response, SSM for recovery, ticketing for documentation).

Detective in the SOC dashboard
A typical SOC dashboard has:

Security Hub: active findings

GuardDuty: threat detection feed

Detective: investigation workspaces (one per active incident)

CloudTrail: raw audit log queries

Macie: data exposure findings

Each service plays a specific role. Detective is where the analyst spends most of their time during an active investigation.

Lessons / Gotchas
Detective requires GuardDuty. If GuardDuty is disabled, Detective cannot be enabled. The org's SCP blocks both.

Behavior graph takes 2-4 hours to populate. On first enable, there is no data to investigate. Plan ahead - enable Detective before you need it.

Detective ingests 14 days of historical data on creation. After 14 days, only new data is added. This means investigations of old incidents require querying CloudTrail directly (not Detective).

The behavior graph costs $1/GB of ingested CloudTrail events. For a high-volume account, this can be $100-1000/month.

Detective is region-specific. Findings in eu-north-1 are investigated in eu-north-1's Detective graph. Cross-region investigations require multiple graphs.

Detective does not replace CloudTrail. It is a visualization and analysis layer on top of CloudTrail. When you need raw event details, you query CloudTrail directly.

The "baseline" is only 14 days of history. If a user's normal behavior is rare (e.g., the IAM user only logs in once a month), the baseline may not have data. Detective will flag "no baseline" - this is a signal that requires human judgment.

Detective is not a SIEM. It does not have alerting, correlation rules, or ticketing. It is an investigation workspace. SIEM functionality requires a separate tool (Splunk, Elastic, Sumo Logic).

The behavior graph is per-graph, not per-account by default. For an organization, the management account creates one graph and invites member accounts. Each account's data appears in the graph as a separate entity.

Detective cannot be exported. The behavior graph exists only inside Detective. For retention or external analysis, query CloudTrail directly.

Files
policies/behavior-graph-config.json - the graph creation config (design mode)

policies/member-account-config.json - org member enrollment config (design mode)

policies/investigation-patterns.json - the three investigation playbooks (reference)

detective-probe-result.txt - the SCP denial error message

Real-World Application
The SOC Analyst's Workflow
Detective is the primary investigation tool for most AWS SOCs. A typical day:

Morning: review overnight findings in Security Hub

For each high-severity finding: open Detective, investigate, determine if incident

For real incidents: document scope in Detective, initiate response

Track investigation findings for post-incident review

An analyst without Detective would query CloudTrail directly for every investigation. This is slow (minutes to hours per investigation) and error-prone (easy to miss connections). Detective reduces investigation time by 10-100x.

The Pentest Debrief
After a red team engagement, Detective is used to:

Trace the red team's path through the environment

Identify which detections fired and which didn't

Understand what the red team accomplished (for scope of the exercise)

Improve detection rules based on gaps

This is the "purple team" workflow - using Detective to bridge red team offense and blue team defense.

The Audit Investigation
When auditors ask "what happened with resource X on date Y":

Detective shows all activity on X on Y

CloudTrail provides the raw event details

Config provides the configuration changes

Combined: a complete picture for audit response

The Insider Threat Investigation
For suspected insider activity:

Detective shows the user's full API call history

Baseline comparison shows anomalies

Cross-referenced with HR data (who is this user, what is their role)

Privacy-preserving: Detective shows what was accessed, not the content

The Combined Detection and Investigation Stack
Across all Phase 4 labs:

Service    Role    Status
CloudTrail (4.1)    Audit log    Working
GuardDuty (4.2)    Threat detection    SCP-blocked
Security Hub (4.3)    Aggregation    SCP-blocked
Config (4.4)    Compliance tracking    Working
Detective (4.5)    Investigation    SCP-blocked
EventBridge + Lambda (4.6)    Auto-response    Working
The pattern: the org allows audit (CloudTrail, Config) but blocks detection/investigation. This is a common enterprise governance choice - audit and compliance are distributed, detection and investigation are centralized.

The Bottom Line
Detective is the investigation layer on top of GuardDuty findings

The behavior graph links entities (users, roles, instances) and events (API calls, network connections)

It answers "what happened" and "how" - not "is this bad" (GuardDuty's job)

Three main playbooks: compromised instance, leaked credential, cryptomining

Behavior graph takes 2-4 hours to populate

Detective is the primary tool for SOC analysts during investigations

The org's SCP blocks Detective along with GuardDuty, Macie, Security Hub, Network Firewall, IAM CreateGroup

In an unblocked account, Detective is enabled alongside GuardDuty from day one

The investigation playbooks in this lab are directly applicable to any GuardDuty investigation
