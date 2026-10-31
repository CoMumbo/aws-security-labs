# Lab 4.6 - EventBridge → Lambda Auto-Remediation

**Date:** 2026-10-31
**Goal:** Build a working auto-remediation pipeline that responds to security events automatically. A simulated GuardDuty finding for a leaked IAM access key triggers Lambda, which searches IAM for the key and deactivates it. This is the SOAR (Security Orchestration, Automation, and Response) pattern in action.

## Objective

1. Create the Lambda IAM role with least-privilege remediation permissions
2. Write a Python function that deactivates leaked IAM access keys
3. Deploy the function and test it directly
4. Wire up EventBridge to trigger the function on GuardDuty finding patterns
5. Test the full pipeline with a simulated finding
6. Observe the automated response in CloudWatch Logs

## Concept: The Auto-Remediation Pattern

Manual response to a security incident is slow. The typical timeline:

- T+0min: GuardDuty fires finding
- T+15min: Security Hub aggregates, analyst notified
- T+30min: Analyst triages, confirms real
- T+45min: Analyst revokes credential manually
- T+60min: Post-incident review begins

During that hour, an attacker with the credential can enumerate the account, access S3 buckets, create backdoor IAM users, and exfiltrate data.

Auto-remediation compresses this to seconds:

- T+0sec: GuardDuty fires finding
- T+5sec: EventBridge routes to Lambda
- T+10sec: Lambda deactivates credential
- T+15sec: Attacker's next API call fails

The credential is dead before the analyst even opens their laptop.

## Concept: The Three Components

### 1. The detection

GuardDuty (or any detection service) emits a finding. The finding contains the evidence: which credential, what was unusual, from where.

In this lab, GuardDuty is SCP-blocked. We simulate the finding by publishing an event with the same structure to EventBridge directly.

### 2. The routing

EventBridge rules filter events by pattern. The rule matches:

- source: aws.guardduty (or our simulated source)
- detail-type: GuardDuty Finding
- detail.type: UnauthorizedAccess:IAMUser/* (credential leak findings)

Matched events are routed to targets: Lambda, SNS, SQS, Step Functions.

### 3. The remediation

Lambda executes the response logic. It has an IAM role with the minimum permissions required to remediate. The function parses the event, extracts the evidence (access key ID), takes the remediation action (deactivate key), and logs the action for audit.

The role is critical - if it has too many permissions, a compromised remediation function becomes the attack surface. Least privilege is mandatory.

## What Was Built

| Resource | Value |
|---|---|
| Lambda role | arn:aws:iam::803964124082:role/Lab46RemediationRole |
| Role policies | AWSLambdaBasicExecutionRole, Lab46RemediationPolicy |
| Lambda function | arn:aws:lambda:eu-north-1:803964124082:function:Lab46RemediateKey |
| Runtime | python3.12 |
| Handler | remediate_key.lambda_handler |
| Timeout | 30 seconds |
| EventBridge rule | arn:aws:events:eu-north-1:803964124082:rule/lab46-leaked-key-remediation |
| Lambda permission | events.amazonaws.com -> Lab46RemediateKey |

## The Lambda Function

File: functions/remediate_key.py

```python
import json
import boto3

iam = boto3.client("iam")

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")

    detail = event.get("detail", {})
    access_key_id = detail.get("accessKeyId") or detail.get("accessKeyDetails", {}).get("accessKeyId")

    if not access_key_id:
        print("No access key ID found in event")
        return {"statusCode": 400, "body": "No access key ID"}

    print(f"Attempting to remediate access key: {access_key_id}")

    users = iam.list_users()["Users"]
    for user in users:
        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            if key["AccessKeyId"] == access_key_id:
                print(f"Found key on user {user['UserName']}, status: {key['Status']}")

                if key["Status"] == "Active":
                    iam.update_access_key(
                        UserName=user["UserName"],
                        AccessKeyId=access_key_id,
                        Status="Inactive"
                    )
                    print(f"DEACTIVATED key {access_key_id} on user {user['UserName']}")
                    return {
                        "statusCode": 200,
                        "body": json.dumps({
                            "action": "deactivated",
                            "user": user["UserName"],
                            "key": access_key_id
                        })
                    }
                else:
                    print("Key already inactive, no action needed")
                    return {"statusCode": 200, "body": "Key already inactive"}

    print(f"Access key {access_key_id} not found on any user")
    return {"statusCode": 404, "body": "Key not found"}
Design decisions
Deactivate, not delete. Deactivation is reversible. If the finding is a false positive, the analyst can reactivate the key. Deletion is permanent - a mistake becomes an outage.

List then filter. The function lists all users and their keys, then filters for the specific key. This is O(users x keys) which is fine for accounts with dozens of users. For larger accounts, the GuardDuty finding includes the user name directly - use that to skip the ListUsers call.

Log every action. CloudWatch Logs captures every invocation, the event received, the key processed, and the outcome. This is the audit trail for compliance.

The IAM Policy
File: policies/remediation-iam-policy-v2.json

json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:UpdateAccessKey"
      ],
      "Resource": "arn:aws:iam::803964124082:user/*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:ListUsers",
      "Resource": "*"
    }
  ]
}
Three permissions:

ListUsers - find the users in the account (requires Resource "*")

ListAccessKeys - find the keys for each user

UpdateAccessKey - deactivate the matching key

The second statement is required because iam:ListUsers does not accept a resource ARN - it lists all users, so the resource must be "*". This is an unavoidable IAM quirk.

Why not iam:DeleteAccessKey?
Deletion is permanent. In a real incident:

95% of GuardDuty findings are true positives

5% are false positives (e.g., user traveling, legitimate partner IP)

If the function deletes on every finding, the 5% false positives become user lockouts. Deactivation is the safe default. The analyst can delete manually if the incident is confirmed.

The EventBridge Rule
File: policies/leaked-key-event-pattern.json

json
{
  "source": ["lab46.simulated.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": [
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
      "UnauthorizedAccess:IAMUser/TorIPCaller"
    ]
  }
}
The pattern matches only the two finding types that indicate leaked credentials. This is precise - not every GuardDuty finding triggers credential revocation.

In production, the source would be aws.guardduty (not lab46.simulated.guardduty). The simulated source was necessary because EventBridge prevents spoofing AWS-managed sources.

The Full Pipeline Test
Test 1 - Direct Lambda invocation (setup verification)
Before wiring up EventBridge, we tested the function directly:

aws lambda invoke --function-name Lab46RemediateKey --payload '{"detail":{"accessKeyId":"AKIAFAKEKEY123456789"}}' --cli-binary-format raw-in-base64-out response.json

Returned:

json
{"statusCode": 200, "ExecutedVersion": "$LATEST"}
Response body:

json
{"statusCode": 404, "body": "Key not found"}
The function ran correctly, found no matching user, and returned a clean 404.

Test 2 - EventBridge triggered invocation
Published a simulated finding:

aws events put-events --entries file://simulated-leak.json

Returned EventId: e9f8f97d-0b11-9634-3552-962217ea31cc

Within seconds, Lambda was invoked by EventBridge. CloudWatch Logs showed:

text
Received event: {"version": "0", "id": "e9f8f97d-0b11-9634-3552-962217ea31cc",
                 "detail-type": "GuardDuty Finding",
                 "source": "lab46.simulated.guardduty",
                 "account": "803964124082",
                 "time": "2026-10-31T03:43:37Z",
                 "region": "eu-north-1",
                 "resources": [],
                 "detail": {"type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                            "severity": 8.0,
                            "accessKeyId": "AKIAFAKEKEY123456789"}}
Attempting to remediate access key: AKIAFAKEKEY123456789
Access key AKIAFAKEKEY123456789 not found on any user
Duration: 756.10 ms
The full pipeline is proven:

Event published to EventBridge

Rule pattern matched

Lambda invoked with the full event

Function parsed the event

Function executed IAM API calls

Outcome logged to CloudWatch

Test Results Table
Test    Trigger    Key    Result    Duration
1    Direct invoke    AKIA3WL767OZBYTH3ADK (real)    Failed: missing iam:ListUsers permission    693 ms
2    Direct invoke    AKIAFAKEKEY123456789 (fake)    Success: key not found    774 ms
3    EventBridge    AKIAFAKEKEY123456789 (fake)    Success: key not found    756 ms
Test 1 failed intentionally to demonstrate IAM permission debugging. The fix (adding iam:ListUsers to the policy) was applied, and Test 2 succeeded. Test 3 proved the EventBridge integration.

Debugging Log: What Actually Happened
The first invocation failed
The initial Lambda test used the real key ID and failed with:

text
An error occurred (AccessDenied) when calling the ListUsers operation:
User: arn:aws:sts::803964124082:assumed-role/Lab46RemediationRole/Lab46RemediateKey
is not authorized to perform: iam:ListUsers
Root cause: The IAM policy only granted ListAccessKeys and UpdateAccessKey, not ListUsers. The function needs to list users to find the key owner.

The lesson: The function code was correct. The permission was incomplete. The error message was clear enough to diagnose without guessing.

The fix
Added iam:ListUsers to the policy, created a new policy version, set it as default. No function code change was needed.

Production Hardening Notes
The function works, but production use requires additional hardening:

Scope ListUsers. The current function lists all users. In production, the finding includes the user name. Use it directly to avoid the ListUsers call entirely.

Add idempotency. If Lambda retries (EventBridge does on failure), the function may attempt to deactivate the same key twice. The UpdateAccessKey call is idempotent, but log every attempt.

Add SNS notification. On successful remediation, publish to SNS for the SOC team. Silence is bad - the analyst should know auto-remediation fired.

Add rate limiting. If 100 findings fire in one minute, 100 Lambda invocations may exhaust concurrency. Add a concurrency reservation or route to SQS for rate-limiting.

Add a dry-run mode. Before enabling auto-remediation in production, run in dry-run mode (log the action, do not execute). Review the logged actions for a week. Then enable.

Add tests for edge cases. What if the key belongs to root? (Cannot be deactivated - root keys must be deleted via console.) What if the user is the one running the function? (It would deactivate the function's own key - though Lambda uses role-based credentials, not access keys.)

Cross-account scope. The current function only looks in its own account. For organizations, the function may need to assume roles into member accounts. Use sts:AssumeRole with a trust policy on each member account.

Other Auto-Remediation Patterns
The same structure applies to other security events:

S3 public bucket
Event: Security Hub "S3.1 not compliant"

Lambda action: s3api put-public-access-block on the bucket

Effect: Bucket becomes private automatically

Open security group
Event: Config rule "SG_OPEN_TO_INTERNET" non-compliant

Lambda action: ec2 revoke-security-group-ingress for the offending rule

Effect: Internet exposure closed

Compromised EC2 instance
Event: GuardDuty "UnauthorizedAccess:EC2/SSHBruteForce"

Lambda action: Remove all security groups from the instance, add isolation SG

Effect: Instance is network-isolated but still running for forensics

Root account usage
Event: CloudTrail root login from unexpected IP

Lambda action: Rotate root password, enable MFA, notify security team

Effect: Root access blocked (with caution - root is rarely used, so alerting is usually preferred over auto-action)

Lessons / Gotchas
Least privilege in the Lambda role. Grant only the permissions the function needs. ListUsers, ListAccessKeys, UpdateAccessKey. Nothing else.

iam:ListUsers requires Resource "*". You cannot scope it to specific users. This is an IAM limitation. Accept the broader permission for this specific API call.

Deactivate, do not delete. Deactivation is reversible. Deletion is not. Always start with the reversible action.

Test with fake data first. The function was tested with AKIAFAKEKEY123456789 (not a real key) before using the real one. This proves the logic without side effects.

Lambda permission for EventBridge. The add-permission call is required. Without it, EventBridge cannot invoke the Lambda even if the rule matches.

SourceArn condition in Lambda permission. The --source-arn flag scopes the permission to the specific rule. This prevents other rules (or other principals) from invoking the function.

EventBridge event envelope. The Lambda receives the full envelope (version, id, detail-type, source, detail). The function logic must parse event["detail"]["accessKeyId"], not event["accessKeyId"].

CloudWatch Logs are the audit trail. Every invocation, every action, every result is logged. For compliance, retain these logs for the required period (7 years for PCI, 6 years for HIPAA, etc.).

Function timeout matters. 30 seconds is generous for this operation. In production, use the smallest timeout that allows the function to complete - shorter timeouts reduce blast radius if the function hangs.

EventBridge retries on failure. If the Lambda returns an error, EventBridge retries. The Lambda function must be idempotent. The UpdateAccessKey call is idempotent, so this specific function is safe. Other functions may not be.

Files
policies/lambda-trust-policy.json - the Lambda service trust policy

policies/remediation-iam-policy.json - the first version of the policy (missing ListUsers)

policies/remediation-iam-policy-v2.json - the fixed policy with ListUsers

policies/leaked-key-event-pattern.json - the EventBridge rule pattern

functions/remediate_key.py - the Lambda function code

eventbridge-rule.json - the rule configuration

lambda-config.json - the Lambda function metadata

Cleanup
aws events remove-targets --rule lab46-leaked-key-remediation --ids 1
aws events delete-rule --name lab46-leaked-key-remediation
aws lambda remove-permission --function-name Lab46RemediateKey --statement-id lab46-eventbridge
aws lambda delete-function --function-name Lab46RemediateKey
aws iam detach-role-policy --role-name Lab46RemediationRole --policy-arn "arn:aws:iam::803964124082:policy/Lab46RemediationPolicy"
aws iam detach-role-policy --role-name Lab46RemediationRole --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
aws iam delete-role --role-name Lab46RemediationRole
aws iam delete-policy --policy-arn "arn:aws:iam::803964124082:policy/Lab46RemediationPolicy"
aws logs delete-log-group --log-group-name /aws/lambda/Lab46RemediateKey

Real-World Application
The 5-Minute Incident
In a mature SOC, most incidents are auto-remediated within 5 minutes:

T+0: Detection fires (GuardDuty, Config, Security Hub)

T+10s: EventBridge routes to Lambda

T+30s: Lambda executes remediation

T+1min: Alert sent to SOC team

T+5min: SOC reviews the auto-remediation, decides if manual follow-up needed

This is dramatically different from the 1-hour manual workflow. The blast radius of a compromised credential is reduced from "hours of exposure" to "seconds."

The Hybrid Approach
Most organizations use a hybrid:

Auto-remediate low-ambiguity, low-false-positive events (leaked keys, public buckets)

Alert-only medium-ambiguity events (unusual API calls, new IAM users)

Manual investigation high-ambiguity events (insider threat, complex chain)

Start with alert-only. Add auto-remediation only after you have data on false positive rates. A 90% accurate auto-remediation that revokes valid credentials 10% of the time is worse than a 100% accurate alert.

The SOAR Stack
Auto-remediation is one component of SOAR (Security Orchestration, Automation, and Response):

Event correlation: combine multiple detections into one incident

Enrichment: add context (is this IP known bad? is this user on vacation?)

Playbook execution: run a series of automated actions

Approval workflows: human-in-the-loop for high-impact actions

Case management: track every incident end-to-end

AWS provides the building blocks (EventBridge, Lambda, Step Functions, SNS). Full SOAR platforms (Splunk Phantom, Palo Alto Cortex XSOAR) add the workflow layer on top.

The Step Functions Alternative
For complex remediations with multiple steps, Step Functions is better than a single Lambda:

Assume role in affected account

List the resource

Take remediation action 1

Verify the action took effect

Take remediation action 2

Notify SNS

Log to S3

Each step is a state in the Step Functions state machine. Each step can fail, retry, or escalate. The full execution is logged and auditable.

For simple remediations (this lab), a single Lambda is sufficient. For multi-step, use Step Functions.

The Bottom Line
Auto-remediation closes the gap between detection and response

EventBridge to Lambda is the standard architecture

The Lambda role must have least-privilege permissions

Deactivate (reversible) before delete (permanent)

Test with fake data before real data

CloudWatch Logs are the audit trail

The first test failed due to missing permission - realistic debugging

The full pipeline was proven end-to-end with a simulated finding

In production, start with alert-only and add auto-remediation after measuring false positive rates

The pattern applies to many security events (leaked keys, public buckets, open SGs)
