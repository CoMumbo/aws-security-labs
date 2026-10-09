# Lab 1.8 - Policy Simulator Deep Dive

**Date:** 2026-10-09
**Goal:** Master the IAM policy simulator by building a scenario matrix that tests multiple actions against multiple resources in a single call, and reading the per-resource decision breakdown.

## Objective

1. Design a realistic developer policy with Allow, resource scoping, and a Deny guardrail
2. Validate it with Access Analyzer
3. Run a matrix simulation testing 9 action/resource pairs in one call
4. Read the per-resource decision breakdown (ResourceSpecificResults)
5. Document the difference between the top-level EvalDecision and the per-resource decisions

## Concept: Simulator Modes and Fields

The simulator has two entry points:

- aws iam simulate-principal-policy - evaluates policies attached to a real principal
- aws iam simulate-custom-policy - evaluates arbitrary policies passed inline or via file

Both return EvaluationResults containing:

- EvalActionName - the action tested
- EvalResourceName - the resource tested (or a template placeholder)
- EvalDecision - the aggregate decision across all resources
- MatchedStatements - which policy statements matched
- ResourceSpecificResults - per-resource decisions when multiple resources are tested

### Aggregate vs Per-Resource

When you test one action against multiple resources, the top-level EvalDecision is the *most restrictive* result. If any resource would be denied, the aggregate reflects that. The ResourceSpecificResults array carries the actual per-resource truth.

This is critical when testing policies that use resource-scoped Allow and Deny statements: the aggregate can look scary (explicitDeny) while the per-resource breakdown shows exactly which resources are permitted and which are not.

## Design Artifact

File: policies/developer-policy.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3DevBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::dev-bucket",
        "arn:aws:s3:::dev-bucket/*"
      ]
    },
    {
      "Sid": "EC2DevInstances",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyProdAccess",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::prod-bucket",
        "arn:aws:s3:::prod-bucket/*"
      ]
    }
  ]
}

The policy grants full read/write on a dev S3 bucket, instance lifecycle actions on EC2, and explicitly denies all S3 access to a prod bucket regardless of any other Allow.

## Validation

### Access Analyzer

aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policies/developer-policy.json

Result: {"findings": []} - clean.

### Simulator Matrix

Command:

aws iam simulate-custom-policy --cli-input-json file://cli-matrix.json

Nine action/resource pairs tested in one call:

| Action | Resource | Decision |
|---|---|---|
| s3:GetObject | dev-bucket/file.txt | allowed |
| s3:PutObject | dev-bucket/file.txt | allowed |
| s3:DeleteObject | dev-bucket/file.txt | allowed |
| s3:ListBucket | dev-bucket | allowed |
| ec2:DescribeInstances | instance/* | implicitDeny |
| ec2:StartInstances | instance/* | allowed |
| ec2:StopInstances | instance/* | allowed |
| ec2:TerminateInstances | instance/* | implicitDeny |
| s3:GetObject | prod-bucket/secret.txt | explicitDeny |

## Key Findings

### 1. DescribeInstances is implicitDeny (surprising)

The policy allows ec2:DescribeInstances with Resource "*". But the simulator returned implicitDeny for the resource arn:aws:ec2:eu-north-1:803964124082:instance/*.

Reason: ec2:DescribeInstances is a wildcard-resource-only action. It does not operate on instance ARNs; it operates on "*". Passing an instance-specific ARN as the resource causes the policy's Resource: "*" to not match the specific resource, resulting in implicit deny.

Lesson: some actions are inherently unscoped (they operate on all resources of a type). Testing them against a specific resource ARN produces misleading results. Always test wildcard-resource actions against "*".

### 2. TerminateInstances is correctly denied

The policy explicitly lists ec2:DescribeInstances, ec2:StartInstances, and ec2:StopInstances, but not ec2:TerminateInstances. The simulator confirms this: implicitDeny.

Lesson: the absence of an Allow for a specific action is what produces implicit deny. The policy does not need a matching Deny.

### 3. The prod-bucket Deny works

The s3:GetObject test against prod-bucket/secret.txt returned explicitDeny. The MatchedStatements field points to the DenyProdAccess statement.

Lesson: explicit Deny in an identity policy overrides any Allow in the same policy (or in other policies attached to the same identity). The aggregate decision is explicitDeny even though the policy also allows s3:GetObject generically for the dev bucket.

### 4. Per-resource decisions carry the truth

For the s3:GetObject action, the top-level EvalDecision is explicitDeny, but the ResourceSpecificResults array shows:

- dev-bucket/file.txt: allowed
- prod-bucket/secret.txt: explicitDeny

The aggregate is not the same as the per-resource reality. Reading only EvalDecision would obscure the fact that some resources are permitted.

## Lessons / Gotchas

1. Test wildcard-resource actions against "*", not against a specific resource. Otherwise, resource-scoped Allows will not match and the result will be a misleading implicitDeny.

2. The top-level EvalDecision is the most restrictive across all resources. Always read ResourceSpecificResults to see per-resource truth.

3. MatchedStatements shows exactly which policy statement(s) drove the decision. This is the fastest way to trace unexpected behavior.

4. Explicit Deny wins, always. The prod-bucket Deny proved this against an Allow in the same policy.

5. Access Analyzer and the Simulator complement each other. Access Analyzer checks policy correctness (syntax, action existence, required fields). The Simulator checks policy effect (what gets allowed, what gets denied, in what combination).

6. Use --cli-input-json for anything with more than a couple of actions or resources. PowerShell's inline quoting is fragile with complex JSON (documented in Labs 1.4 and 1.7).

## Files

- policies/developer-policy.json - the demo policy
- cli-matrix.json - the 9-scenario test

## Real-World Application

The scenario-matrix approach is how IAM policies are validated in CI/CD:

1. Author a policy alongside a set of expected action/resource outcomes
2. Run simulate-custom-policy (or simulate-principal-policy) in the pipeline
3. Fail the build if any expected outcome does not match

This catches the entire class of "I thought this would be allowed" mistakes before a policy ever reaches production. Combined with Access Analyzer validate-policy for structural correctness, it provides two layers of pre-deployment assurance:

- validate-policy: does the policy parse, are the actions real, is the structure correct?
- simulate-*: does the policy produce the intended allow/deny outcomes across the test matrix?

Both layers belong in a policy-as-code pipeline. Running the simulator against a scenario matrix is the standard way to write unit tests for IAM policies.
