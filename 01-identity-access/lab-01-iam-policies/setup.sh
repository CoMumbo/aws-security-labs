#!/bin/bash
# Lab 1.1 - S3 ReadOnly Analyst
# Reproduces: creates the policy, the test user, and attaches them.
# Then validates with the CLI policy simulator.
set -e

POLICY_NAME="S3ReadOnlyAnalyst"
USER_NAME="test-analyst"
TARGET_BUCKET="analyst-data-bucket"

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "Account ID: $ACCOUNT_ID"

# Create the policy
echo ""
echo "Creating policy: $POLICY_NAME"
POLICY_ARN=$(aws iam create-policy \
  --policy-name "$POLICY_NAME" \
  --policy-document file://policies/s3-readonly-analyst.json \
  --description "Read-only access to $TARGET_BUCKET" \
  --query 'Policy.Arn' --output text 2>/dev/null || \
  aws iam get-policy --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}" --query 'Policy.Arn' --output text)

echo "Policy ARN: $POLICY_ARN"

# Create the user (idempotent)
echo ""
echo "Ensuring user exists: $USER_NAME"
aws iam get-user --user-name "$USER_NAME" 2>/dev/null || \
  aws iam create-user --user-name "$USER_NAME"

# Attach policy
echo ""
echo "Attaching policy..."
aws iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$POLICY_ARN"

echo "Done."

# --- Validation via simulator ---
echo ""
echo "=== Simulator Validation ==="
USER_ARN="arn:aws:iam::${ACCOUNT_ID}:user/${USER_NAME}"

echo ""
echo "Test 1: s3:ListAllMyBuckets (expect: allowed)"
aws iam simulate-principal-policy \
  --policy-source-arn "$USER_ARN" \
  --action-names "s3:ListAllMyBuckets" \
  --query 'EvaluationResults[0].EvalDecision' --output text

echo ""
echo "Test 2: s3:DeleteObject on $TARGET_BUCKET (expect: implicitDeny)"
aws iam simulate-principal-policy \
  --policy-source-arn "$USER_ARN" \
  --action-names "s3:DeleteObject" \
  --resource-arns "arn:aws:s3:::${TARGET_BUCKET}/test.txt" \
  --query 'EvaluationResults[0].EvalDecision' --output text

echo ""
echo "Test 3: s3:GetObject on $TARGET_BUCKET (expect: allowed)"
aws iam simulate-principal-policy \
  --policy-source-arn "$USER_ARN" \
  --action-names "s3:GetObject" \
  --resource-arns "arn:aws:s3:::${TARGET_BUCKET}/secret.pdf" \
  --query 'EvaluationResults[0].EvalDecision' --output text

echo ""
echo "Test 4: s3:GetObject on some-other-bucket (expect: implicitDeny)"
aws iam simulate-principal-policy \
  --policy-source-arn "$USER_ARN" \
  --action-names "s3:GetObject" \
  --resource-arns "arn:aws:s3:::some-other-bucket/file.txt" \
  --query 'EvaluationResults[0].EvalDecision' --output text

echo ""
echo "=== Cleanup (uncomment to run) ==="
echo "# aws iam detach-user-policy --user-name $USER_NAME --policy-arn $POLICY_ARN"
echo "# aws iam delete-user --user-name $USER_NAME"
echo "# aws iam delete-policy --policy-arn $POLICY_ARN"