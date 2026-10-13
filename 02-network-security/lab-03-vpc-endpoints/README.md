# Lab 2.3 - VPC Endpoints

**Date:** 2026-10-13
**Goal:** Create a Gateway VPC Endpoint for S3, observe how it modifies the route table, and understand the difference between Gateway and Interface endpoints.

## Objective

1. Snapshot the VPC route table before creating an endpoint
2. Create a Gateway Endpoint for S3
3. Observe the new route and the managed prefix list it uses
4. Inspect the actual S3 IP ranges the prefix list contains
5. Apply a restrictive endpoint policy that limits access to a specific bucket

## Concept: What VPC Endpoints Do

VPC Endpoints let resources inside a VPC reach AWS services without traversing the public internet. They keep traffic on the AWS private backbone.

There are two types:

### Gateway Endpoints

- Supported services: S3 and DynamoDB only
- Attach to a route table
- No ENI created (no IP address in the VPC)
- No hourly charge
- Traffic is routed via an entry in the route table that uses a managed prefix list

### Interface Endpoints (AWS PrivateLink)

- Supported services: most AWS services (SSM, KMS, Secrets Manager, EC2 API, ECR, etc.)
- Create an elastic network interface (ENI) in the subnet with a private IP
- Accessed via DNS name that resolves to the ENI's private IP
- Charged per hour plus per GB processed
- Do not use route tables

The two are fundamentally different mechanisms. A Gateway Endpoint is a route table entry; an Interface Endpoint is a private ENI.

## What Was Built

| Resource | ID |
|---|---|
| VPC | vpc-0b00f49eaaa30977c |
| Main route table | rtb-04e558d836115792a |
| Gateway Endpoint (S3) | vpce-0b3aaea5501ef8cf3 |
| Managed prefix list | pl-c3aa4faa |
| Endpoint policy | AllowOnlyLabBucket |

## Before State: Route Table

Route table rtb-04e558d836115792a before the endpoint existed:

| Destination | Target | Origin |
|---|---|---|
| 172.31.0.0/16 | local | CreateRouteTable |
| 0.0.0.0/0 | igw-0085a1b240d0545ac | CreateRoute |

Traffic to S3 was routed to the internet gateway. It would leave the VPC, traverse the public internet (or AWS's edge network), and reach S3 over public endpoints.

## After State: Route Table

Route table rtb-04e558d836115792a after the endpoint was created:

| Destination | Target | Origin |
|---|---|---|
| 172.31.0.0/16 | local | CreateRouteTable |
| 0.0.0.0/0 | igw-0085a1b240d0545ac | CreateRoute |
| (prefix list pl-c3aa4faa) | vpce-0b3aaea5501ef8cf3 | CreateRoute |

The new route has no CIDR. It uses the managed prefix list pl-c3aa4faa, which contains the current IP ranges of S3 in this region. Traffic matching this prefix list is sent directly to the endpoint and never leaves the AWS network.

## The Prefix List Contents

Command:

aws ec2 get-managed-prefix-list-entries --prefix-list-id pl-c3aa4faa --query "Entries[].Cidr" --output text

Output:

16.12.10.0/23
16.12.9.0/24
3.5.216.0/22
52.95.169.0/24
52.95.170.0/23

These are the current S3 endpoint IP ranges for eu-north-1. AWS keeps this list automatically updated. Because the route references the prefix list rather than a hardcoded CIDR, no user action is needed when AWS adds or removes S3 IPs.

## Setup Commands

### 1. Create the endpoint

aws ec2 create-vpc-endpoint --vpc-id vpc-0b00f49eaaa30977c --service-name com.amazonaws.eu-north-1.s3 --vpc-endpoint-type Gateway --route-table-ids rtb-04e558d836115792a

Returned:

- VpcEndpointId: vpce-0b3aaea5501ef8cf3
- VpcEndpointType: Gateway
- State: available
- PolicyDocument: default allow-all
- NetworkInterfaceIds: [] (no ENI, as expected for Gateway type)

### 2. Replace the default endpoint policy

File: policies/endpoint-policy.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOnlyLabBucket",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::lab23-test-bucket",
        "arn:aws:s3:::lab23-test-bucket/*"
      ]
    }
  ]
}

Apply:

aws ec2 modify-vpc-endpoint --vpc-endpoint-id vpce-0b3aaea5501ef8cf3 --policy-document file://policies/endpoint-policy.json

### 3. Verify the endpoint policy

aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-0b3aaea5501ef8cf3 --query "VpcEndpoints[].PolicyDocument" --output text

Confirmed the endpoint is now limited to s3:GetObject and s3:ListBucket on a single bucket.

## Important Misconception: Principal "*"

The endpoint policy uses Principal: "*". This does not mean anyone on the internet. Endpoint policies are evaluated only for traffic entering through the endpoint, which is a private path reachable only from inside the VPC (or from connected networks).

A Principal of "*" in an endpoint policy means "any principal within the scope of this endpoint" — that is, any identity that can reach the endpoint over the private path. It is not a public grant.

A common misunderstanding is to confuse this with a bucket policy or a resource policy that also uses Principal "*". Those operate on the service endpoint reachable via the internet, and a Principal "*" there is a genuine public grant.

## Gateway vs Interface Endpoints

| Aspect | Gateway Endpoint | Interface Endpoint |
|---|---|---|
| Supported services | S3, DynamoDB | Most AWS services |
| Attachment point | Route table | Subnet (ENI) |
| Creates an ENI? | No | Yes |
| Has a private IP in the VPC? | No | Yes |
| Uses DNS? | No | Yes |
| Cost | Free | Hourly + per GB |
| Accessible from on-premises / VPN? | No (unless using prefix list manually) | Yes |
| Policy document | Yes | Yes |
| Security groups | Not applicable | Yes (the ENI has an SG) |

## Lessons / Gotchas

1. Gateway Endpoints are free and only cover S3 and DynamoDB. For any other service, an Interface Endpoint (PrivateLink) is required, and it costs money.

2. Gateway Endpoints work through route tables, not ENIs. There is no IP address, no security group, and no DNS. The route table entry is the entire mechanism.

3. The route target is a managed prefix list, not a CIDR. This is why no manual update is required when AWS adds S3 IP ranges.

4. Endpoint policies are additive to identity policies and bucket policies. For an action to succeed through the endpoint, the identity policy must allow it, the endpoint policy must allow it, AND (for S3) the bucket policy must allow it. All three are evaluated.

5. Principal "*" in an endpoint policy is not a public grant. The endpoint is private. Do not confuse it with Principal "*" in a bucket policy, where it is public.

6. Gateway Endpoints work only from inside the VPC. If your traffic originates on-premises (via VPN or Direct Connect), a Gateway Endpoint will not help; you need an Interface Endpoint or to route through a proxy in the VPC.

7. Interface Endpoints create ENIs, which count against your subnet's IP space. In small subnets, this matters.

## Files

- policies/endpoint-policy.json - restrictive endpoint policy
- vpce-snapshot.json - endpoint state immediately after creation
- vpce-final.json - endpoint state after policy replacement
- route-table-after-vpce.json - route table with the new endpoint route
- prefix-list-entries.json - the S3 IP ranges behind the prefix list

## Real-World Application

VPC Endpoints are standard in any architecture that uses private subnets without NAT Gateway egress, or that has compliance requirements to keep traffic off the public internet:

- Data exfiltration prevention. An endpoint policy that allows only a specific bucket prevents compromised EC2 instances from uploading stolen data to attacker-controlled S3 buckets.

- Cost reduction. S3 and DynamoDB Gateway Endpoints are free and remove NAT Gateway data-processing charges for large data transfers. This is often the single biggest cost saving in a private-subnet architecture.

- Compliance. PCI, HIPAA, and FedRAMP often require that regulated data does not traverse public networks. Gateway Endpoints keep S3 traffic on the AWS backbone.

- Private service access. Interface Endpoints are how workloads call SSM, KMS, Secrets Manager, and ECR without internet egress.

A common real-world pattern in regulated industries is: private subnets with no NAT Gateway, plus Gateway Endpoints for S3 and DynamoDB, plus Interface Endpoints for the specific services the workloads need. This keeps all traffic on AWS's network, satisfies compliance, and is often cheaper than running NAT.

A second common pattern uses the endpoint policy as a data-boundary control. Even if an attacker has valid AWS credentials and can call s3:PutObject, the endpoint policy blocks uploads to any bucket except the allowed one. This is a defense-in-depth control that does not rely on the identity policies being correct.
