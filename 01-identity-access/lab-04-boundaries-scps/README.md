# Lab 1.4 - Permission Boundaries and SCPs

**Date:** 2026-10-08
**Goal:** Understand the full AWS policy evaluation chain, build a permissions boundary that limits an identity to S3 read-only, and prove the boundary effect using the AWS IAM policy simulator.

## Objective

1. Design an over-permissive identity policy (s3, ec2, iam reads)
2. Design a permissions boundary that only allows S3 read
3. Simulate the combined effect and confirm the boundary caps the identity
4. Document the difference between SCPs and permissions boundaries

## Concept: Policy Evaluation Chain

Every authorization decision passes through multiple layers:

1. SCP (org-level guardrail)
2. Resource-based policy (e.g., S3 bucket policy)
3. Identity-based policy (attached to the user/role)
4. Permissions boundary (ceiling for that identity)
5. Session policy (passed during AssumeRole)

Decision logic:

- Any layer returning an explicit Deny results in a denied request
- Otherwise, every relevant layer must Allow for the request to succeed
- If no layer explicitly allows, the result is implicit deny

### SCP vs Permissions Boundary

| Aspect | SCP | Permissions Boundary |
|---|---|---|
| Who applies it | AWS Organizations (management account) | IAM admin in the account |
| Scope | All principals in the account | One specific user or role |
| Purpose | Organizational guardrail | Delegation ceiling |
| Visible from member account | No | Yes |

A permissions boundary does NOT grant permissions. It only caps them.

## Design Artifacts

### Over-permissive identity policy

File: policies/over-permissive-identity.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEverythingWeMightWant",
      "Effect": "Allow",
      "Action": ["s3:*", "ec2:*", "iam:ListUsers", "iam:ListRoles"],
      "Resource": "*"
    }
  ]
}

### Permissions boundary

File: policies/s3-only-boundary.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", "s3:ListAllMyBuckets"],
      "Resource": "*"
    }
  ]
}

## Validation

The simulator's --policy-input-list file://x.json flag treats a multi-line file as a list of policy documents, one per line. A single multi-line JSON policy is parsed character-by-character, producing a misleading validation error:

Value at 'permissionsBoundaryPolicyInputList' failed to satisfy constraint: Member must have length less than or equal to 10

Fix: use --cli-input-json with policies embedded as JSON strings, which passes the entire request as a single document.

### Test Results

| # | Action | EvalDecision | AllowedByPermissionsBoundary |
|---|---|---|---|
| 1 | s3:GetObject | allowed | true |
| 2 | ec2:RunInstances | implicitDeny | false |
| 3 | iam:CreateUser | implicitDeny | false |
| 4 | s3:PutObject | implicitDeny | false |

### Interpretation

- Test 1 - action is in both the identity policy and the boundary. Result: allowed.
- Test 2 - identity policy allows ec2:*, but the boundary only permits S3 read. Result: implicitDeny.
- Test 3 - action is in neither policy. Result: implicitDeny.
- Test 4 - the identity policy allows s3:* (which includes s3:PutObject), but the boundary only lists s3:GetObject, s3:ListBucket, and s3:ListAllMyBuckets. Result: implicitDeny.

The PermissionsBoundaryDecisionDetail field in the simulator output is the critical signal. When it shows AllowedByPermissionsBoundary: false alongside an action the identity policy would otherwise permit, the boundary is what stopped the request.

### Sample command

aws iam simulate-custom-policy --cli-input-json file://cli-input-01.json

Files cli-input-01.json through cli-input-04.json are included as reproducible test cases.

## Lessons / Gotchas

1. The file:// flag for --policy-input-list expects one policy per line. A multi-line single-policy JSON file is parsed character-by-character, producing a misleading "length must be <= 10" validation error. Fix: use --cli-input-json with the policies embedded as JSON strings.

2. Permissions boundaries do not grant anything. They only limit. An identity with a boundary but no identity policy has zero permissions.

3. Both sides must allow. For a request to succeed with a boundary attached, the identity policy must Allow AND the boundary must Allow. Test 4 demonstrated this in reverse: identity allowed, boundary did not.

4. PermissionsBoundaryDecisionDetail tells you exactly whether the boundary was the limiting factor.

5. SCPs and boundaries look similar but operate at different levels. SCPs are organizational, boundaries are per-identity. In a restricted member account, SCPs are invisible to the account itself. This lab hit the same wall (from Lab 1.2's discovery): the SCP p-whl27g4i blocks iam:CreateGroup, so the demonstration had to run through the simulator rather than live users.

6. Explicit Deny is order-independent. A Deny anywhere in the chain (SCP, boundary, identity, resource, session) denies the request, regardless of Allows elsewhere.

## Files

- policies/over-permissive-identity.json - the demo identity policy
- policies/s3-only-boundary.json - the demo permissions boundary
- cli-input-01.json through cli-input-04.json - reproducible simulator requests

## Real-World Application

Permissions boundaries are the standard mechanism for delegating IAM administration safely:

- Give a developer the ability to create IAM users/roles, but attach a boundary that caps what those identities can ever do
- Prevent privilege escalation: the developer cannot create an admin user because the boundary forbids it, even though their identity policy technically allows iam:CreateUser
- Enforce a consistent ceiling across an entire team by requiring the boundary on every identity they create

The simulator-driven validation approach used here is how this is tested in CI/CD pipelines that enforce policy-as-code: every IAM policy change is validated against a target boundary before merge.
