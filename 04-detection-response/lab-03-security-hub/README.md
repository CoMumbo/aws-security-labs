# Lab 4.3 - Security Hub - Aggregated Findings and Compliance Standards

**Date:** 2026-10-30
**Goal:** Understand Security Hub's role as the aggregation layer for all AWS security findings, its compliance standards, and its integration with EventBridge. Design mode due to SCP block, but the EventBridge response rule was built and tested.

## Objective

1. Understand what Security Hub is and what it aggregates
2. Learn the three pricing tiers
3. Understand compliance standards (FSBP, CIS, PCI DSS)
4. Design the hub configuration and standard enablement
5. Build the EventBridge rule for high-severity findings
6. Document the finding aggregation model
7. Identify which Security Hub controls are already passing in this account (from prior labs)

## Concept: What Security Hub Is

Security Hub is the aggregation and compliance layer of the AWS security stack. It does three things:

### 1. Aggregates findings

Security Hub collects findings from:
- GuardDuty (threat detection)
- Macie (data discovery)
- Inspector (vulnerability scanning)
- Config (compliance)
- IAM Access Analyzer (unused access)
- Firewall Manager (network policy)
- Third-party tools (Splunk, CrowdStrike, Palo Alto, etc.)
- Custom findings (via the Security Hub API)

All findings appear in one dashboard with a unified schema. This is the "single pane of glass" that security teams need.

### 2. Runs compliance standards

Security Hub runs continuous compliance checks against frameworks:

- **AWS Foundational Security Best Practices (FSBP)** - 250+ controls across 40+ services, AWS's recommended baseline
- **CIS AWS Foundations Benchmark** - industry-standard configuration baseline
- **PCI DSS** - payment card industry compliance
- **NIST 800-53** - US federal compliance
- **ISO 27001** - international information security
- **SOC 2** - service organization controls
- **HIPAA** - healthcare (via third-party standards)

Each control produces a PASSED, FAILED, or WARNING finding. The aggregated score shows overall compliance posture.

### 3. Routes findings

Findings flow to EventBridge with source `aws.securityhub` and detail-type `Security Hub Findings - Imported`. Rules can route specific findings to SNS, Lambda, or SIEM.

## Concept: The Three Pricing Tiers

Security Hub is priced in tiers:

### Tier 1: Foundational Security Best Practices

- Free
- AWS FSBP standard included
- Aggregates findings from GuardDuty, Macie, Inspector, Config, Access Analyzer
- Dashboard and workflow management
- 10,000 findings per region included

### Tier 2: CIS AWS Foundations Benchmark

- ~$0.0010 per check per region per month
- CIS 1.4 and 1.5 standards
- Additional controls beyond FSBP

### Tier 3: PCI DSS

- ~$0.0010 per check per region per month
- PCI DSS 3.2.1 and 4.0 standards
- Required for organizations processing payment cards

Most organizations start with Tier 1 (free). Tier 2 and 3 are added for specific compliance requirements.

## Concept: The Finding Schema

Security Hub uses the AWS Security Finding Format (ASFF), a standardized JSON schema. Every finding from every service is normalized to ASFF.

Key fields:

- `Id` - unique finding identifier
- `ProductArn` - the source service
- `GeneratorId` - the specific check that fired
- `AwsAccountId`, `Region`, `Resources`
- `Severity.Label` - INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
- `Title`, `Description`
- `Compliance.Status` - PASSED, FAILED, WARNING, NOT_AVAILABLE
- `Workflow.Status` - NEW, NOTIFIED, RESOLVED, SUPPRESSED
- `RecordState` - ACTIVE or ARCHIVED

The `Severity.Label` and `Compliance.Status` fields are what EventBridge rules filter on.

## Concept: The Workflow Status

Every finding has a workflow status that the security team manages:

- **NEW** - not yet reviewed
- **NOTIFIED** - owner has been notified
- **RESOLVED** - fixed
- **SUPPRESSED** - intentionally ignored (false positive, accepted risk)

This is what makes Security Hub more than a dashboard - it's a workflow tool. Findings aren't just displayed; they're tracked through resolution.

## The SCP Blocker

The Security Hub API was rejected:
User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to perform:
securityhub:DescribeHub on resource:
arn:aws:securityhub:eu-north-1:803964124082:hub/default with an explicit deny
in a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

text

This is the **sixth service** blocked by p-whl27g4i:

1. IAM CreateGroup
2. GuardDuty
3. Macie
4. Access Analyzer (management)
5. Network Firewall
6. Security Hub

The pattern is clear: all detection, data security, and aggregation services are blocked at the member account level. These are managed centrally by the organization.

## Design Artifacts

### 1. Hub configuration

File: policies/securityhub-hub-config.json

```json
{
  "EnableDefaultStandards": true,
  "ControlFindingGenerator": "SECURITY_CONTROL",
  "AutoEnableControls": true
}
Settings:

EnableDefaultStandards: true - enable FSBP automatically on hub creation

ControlFindingGenerator: SECURITY_CONTROL - use the new control IDs (e.g., S3.1) rather than the old config rule IDs. Recommended.

AutoEnableControls: true - new controls added to standards are enabled automatically

2. FSBP standard enablement
File: policies/enable-fsbp.json

json
{
  "StandardsArn": "arn:aws:securityhub:eu-north-1::standards/aws-foundational-security-best-practices/v/1.0.0",
  "StandardsInput": {}
}
The StandardsInput is empty because FSBP has no configurable parameters. Enabling the standard is enough.

3. CIS standard enablement
File: policies/enable-cis.json

json
{
  "StandardsArn": "arn:aws:securityhub:eu-north-1::standards/cis-aws-foundations-benchmark/v/1.4.0",
  "StandardsInput": {}
}
Same structure for CIS 1.4.0. The version matters - 1.4 and 1.5 have different checks.

The EventBridge Response Rule
File: policies/securityhub-event-pattern.json

json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "Severity": {"Label": ["CRITICAL", "HIGH"]},
      "Compliance": {"Status": ["FAILED"]},
      "Workflow": {"Status": ["NEW"]}
    }
  }
}
This pattern matches findings that are:

From Security Hub (aws.securityhub source)

Of type Security Hub Findings - Imported

Severity CRITICAL or HIGH

Compliance FAILED (non-compliant)

Workflow NEW (not yet triaged)

Created:

aws events put-rule --name lab43-securityhub-findings --event-pattern file://policies/securityhub-event-pattern.json --state ENABLED

Returned ARN: arn:aws:events:eu-north-1:803964124082:rule/lab43-securityhub-findings

This rule is active and waiting. When Security Hub is available (via the org or in a different account), findings will flow through this rule to the configured target (SNS, Lambda, etc.).

What Security Hub Would Show in This Account
If Security Hub were enabled, it would run FSBP controls against every resource. Based on the labs completed, here's what the compliance score would look like:

Controls already passing (fixed in labs)
S3.1 - Block Public Access on buckets: PASSING (enabled at account level in Lab 3.2)

S3.2 - Block Public Access at account level: PASSING (enabled in Lab 3.2)

S3.8 - Block Public Access on specific buckets: PASSING

EBS.1 - EBS default encryption: PASSING (enabled in Lab 3.6)

CloudTrail.1 - CloudTrail multi-region trail: PASSING (enabled in Lab 4.1)

CloudTrail.2 - CloudTrail log file validation: PASSING (enabled in Lab 4.1)

CloudTrail.4 - CloudTrail log file encryption: PASSING (S3 SSE-KMS default)

IAM.1 - Root account access key: PASSING (never created)

IAM.2 - IAM user policy attached to user: depends on whether direct policies exist

Controls that would FAIL
IAM.6 - Hardware MFA for root: FAILING (never enabled MFA)

GuardDuty.1 - GuardDuty enabled: FAILING (SCP-blocked)

GuardDuty.2 - GuardDuty EKS audit logs: FAILING

GuardDuty.3 - GuardDuty S3 protection: FAILING

Macie.1 - Macie enabled: FAILING (SCP-blocked)

Macie.2 - Macie S3 publishing: FAILING

IAM.4 - Root user access key: FAILING if any access key exists

Possibly more depending on resource inventory

The aggregate score would be higher than a default account because of the fixes from Labs 3.2, 3.6, and 4.1, but not 100% because GuardDuty and Macie are blocked.

The Value of the Score
Without Security Hub, a security review relies on manual checks. With Security Hub, the score is a single number ("62% compliant") that:

Makes progress measurable over time

Makes gaps visible (which controls are failing and why)

Enables remediation tracking (which team is responsible for each failing control)

Concept: The Multi-Account Aggregation Model
For an AWS Organization, Security Hub has a critical feature: cross-account aggregation.

Management account enables Security Hub with delegated admin

Designated security account becomes the aggregation point

All member accounts send findings to the security account

The security account sees a single dashboard for the entire org

This is why the SCP blocks member accounts - the management account controls Security Hub org-wide. If any member account could enable Security Hub independently, the management account would have no unified view.

The SCP is enforcing governance, not restricting legitimate member account activity.

Lessons / Gotchas
Security Hub is the aggregation layer, not the detection layer. It doesn't detect threats itself; it collects findings from services that do.

FSBP is free but incomplete. It covers 250+ controls, but not the deep compliance requirements of PCI DSS or HIPAA. Those require Tier 2 or 3.

AutoEnableControls can surprise you. New controls are added to FSBP regularly. If auto-enable is on, those controls apply immediately and may start failing. Plan for review workflows.

The workflow status matters. A finding that is RESOLVED stops appearing in dashboards, but the underlying control is still checked. If the resource reverts, a new NEW finding appears.

Suppressed findings are still evaluated. Suppression hides them from the dashboard but the control continues to be checked. If you suppress a failing control, you're saying "I know and I accept the risk." That's fine for documented exceptions.

The cross-account aggregation requires explicit setup. It doesn't work automatically. The management account must designate an admin, and member accounts must be invited or auto-enrolled.

Security Hub and GuardDuty are different. GuardDuty detects specific threats (compromised credentials, crypto mining). Security Hub checks configuration state (is MFA enabled, is encryption on). Both are needed.

Findings are searchable for 90 days. For longer retention, export to S3 (via the EventBridge rule in this lab).

The finding format is ASFF (Amazon Security Finding Format). All findings are normalized to this schema. Third-party tools must also normalize to ASFF to appear in Security Hub.

The EventBridge source is aws.securityhub, not aws.security-hub. The detail-type is Security Hub Findings - Imported with spaces in the name. Exact matching is required.

Files
policies/securityhub-hub-config.json - the hub configuration (design mode)

policies/enable-fsbp.json - FSBP standard enablement (design mode)

policies/enable-cis.json - CIS standard enablement (design mode)

policies/securityhub-event-pattern.json - the EventBridge event pattern (deployed)

eventbridge-rule.json - the rule that was created

rule-state.json - the rule state confirmation

Cleanup
aws events delete-rule --name lab43-securityhub-findings

Real-World Application
The Compliance Dashboard
For a regulated industry (finance, healthcare), Security Hub is the compliance dashboard:

View FSBP, CIS, and PCI DSS scores on one page

Drill down to failing controls by service

Assign remediation owners

Track progress week over week

Export to auditors as evidence

This is the single most valuable service for "prove we are compliant" conversations.

The SOC Workflow
Security Hub is the SOC's primary workflow tool:

Dashboard review - see new HIGH/CRITICAL findings

Triage - classify as false positive, accepted risk, or real

Assign - assign to the right team (network, IAM, data)

Track - workflow status changes reflect progress

Verify - after remediation, the finding transitions to PASSED

Without Security Hub, this workflow runs on spreadsheets and email. With it, the workflow is structured, auditable, and trackable.

The Org-Wide Posture
For a 100-account organization:

100 separate GuardDuty configurations

100 separate Macie configurations

100 separate Config rules

→ 1 aggregated view in Security Hub

The security team manages 1 view, not 100. This is the operational value of the aggregation layer.

The Auto-Remediation Pattern
Once findings flow to EventBridge, Lambda can remediate automatically:

Security Hub fires "S3.1 not compliant" finding

EventBridge rule matches

Lambda blocks public access on the bucket

Finding transitions to PASSED on next scan

Workflow status auto-updates to RESOLVED

This "self-healing" pattern is increasingly common. It reduces the SOC's workload for known-issue categories while keeping the SOC focused on novel findings.

The Bottom Line
Security Hub aggregates all AWS security findings into one dashboard

It runs compliance standards (FSBP free, CIS/PCI paid)

It uses ASFF, a standardized finding schema

The workflow status makes it a tracking tool, not just a dashboard

Cross-account aggregation is the enterprise pattern

SCPs typically block member accounts - Security Hub is managed org-wide

The EventBridge rule pattern allows automated response

Six services are now blocked by the same SCP - all detection/aggregation services

The account has multiple FSBP controls already passing (from prior labs)
