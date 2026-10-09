# Lab 1.5 - IAM Access Analyzer

**Date:** 2026-10-09
**Goal:** Understand Access Analyzer, its role in finding unintended external access, and its policy validation API. Adapted mid-lab after the analyzer management APIs were found to be blocked by an SCP.

## Objective

1. Understand Access Analyzer's purpose and zones of trust
2. Attempt to create an analyzer and view findings
3. Probe what Access Analyzer APIs still work under the SCP
4. Validate IAM policies across all four policy types using the validate-policy API
5. Document the boundary between what is and is not possible in this account

## Concept: What Access Analyzer Does

Access Analyzer analyzes resource-based policies on S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, SNS topics, Secrets Manager secrets, and EFS file systems. It compares what those policies allow against a defined zone of trust.

Zones of trust:

- Account - only this AWS account is trusted
- Organization - every account in the AWS Org is trusted
- Internet - stricter mode where only explicitly trusted external entities are not flagged

Findings flag resources reachable by principals outside the zone of trust.

## The SCP Blocker

The list-analyzers call was rejected:
