# Lab 2.2 - VPC Flow Logs

**Date:** 2026-10-13
**Goal:** Enable VPC Flow Logs, generate real traffic, and analyze the captured records. This lab captures live internet scanning against a freshly-public EC2 instance, plus legitimate outbound DNS/NTP traffic.

## Objective

1. Create a CloudWatch Logs group and an IAM role for Flow Logs delivery
2. Enable VPC Flow Logs on the default VPC with traffic-type ALL
3. Generate real traffic by launching an EC2 instance and giving it internet access
4. Read and decode the flow log record format
5. Interpret both REJECT (inbound probes) and ACCEPT (outbound DNS/NTP) records

## Concept: What VPC Flow Logs Capture

Flow Logs record IP traffic metadata for a VPC, subnet, or ENI. They capture:

- Source and destination IP
- Source and destination port
- Protocol
- Packet and byte counts
- Start and end timestamps
- Action (ACCEPT or REJECT based on SG/NACL decision)
- Log status (OK or NODATA)

They do NOT capture:
- Packet payload
- Traffic to the EC2 metadata service (169.254.169.254) from the instance itself
- Traffic to/from the DNS resolver at the VPC CIDR base + 2
- Windows license activation traffic
- DHCP traffic within the VPC
- Traffic to the reserved Amazon DNS at 169.254.169.253

### Default Record Format

${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}

### NODATA Records

Emitted when the ENI exists but no traffic was observed in the aggregation window. All fields except version, account-id, interface-id, timestamps, and log-status are "-".

NODATA does not mean a problem; it means "still here, just idle."

## What Was Built

| Resource | ID |
|---|---|
| Log group | /aws/vpc/flowlogs/lab22 |
| IAM role | VPCFlowLogsRole (arn:aws:iam::803964124082:role/VPCFlowLogsRole) |
| IAM policy | VPCFlowLogsToCloudWatch |
| Flow log | fl-0c805069859c56f9a |
| VPC | vpc-0b00f49eaaa30977c |
| Subnet | subnet-05696db15eee2b7a2 (172.31.100.0/24) |
| Security group | sg-053e9ea2757f0c4c6 |
| EC2 instance | i-0e5c9f9ea6f2c3822 (t3.micro, Amazon Linux 2023) |
| ENI | eni-0163e40f664bfae3d |
| Elastic IP | eipalloc-0ace3d2eff1982465 |
| Internet gateway | igw-0085a1b240d0545ac |

## Setup Steps

### 1. Create the log group

aws logs create-log-group --log-group-name /aws/vpc/flowlogs/lab22

### 2. Create the trust policy and role

Trust policy grants the Flow Logs service permission to assume the role:

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

Role creation:

aws iam create-role --role-name VPCFlowLogsRole --assume-role-policy-document file://policies/flowlogs-trust-policy.json --description "Role for VPC Flow Logs to write to CloudWatch"

### 3. Attach the CloudWatch Logs permission policy

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }
  ]
}

aws iam create-policy --policy-name VPCFlowLogsToCloudWatch --policy-document file://policies/flowlogs-permissions.json
aws iam attach-role-policy --role-name VPCFlowLogsRole --policy-arn "arn:aws:iam::803964124082:policy/VPCFlowLogsToCloudWatch"

### 4. Enable the flow log

aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-0b00f49eaaa30977c --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs/lab22 --deliver-logs-permission-arn "arn:aws:iam::803964124082:role/VPCFlowLogsRole"

Returned FlowLogId: fl-0c805069859c56f9a

### 5. Generate traffic

Because the default VPC subnet had no route to the internet (the previous IGW had been deleted, leaving a blackhole route), the following steps were required:

1. Created and attached a new internet gateway (igw-0085a1b240d0545ac)
2. Replaced the blackhole route in the main route table (rtb-04e558d836115792a) to point at the new IGW
3. Allocated an Elastic IP (eipalloc-0ace3d2eff1982465) and associated it with the instance
4. Rebooted the instance so it would attempt outbound connections with internet access available

## Sample Flow Log Records

Records observed after the internet path was restored:

REJECT - inbound probes from the internet (destination is the instance, source is external):

2 803964124082 eni-0163e40f664bfae3d 85.217.140.43 172.31.100.171 32901 42567 6 1 52 ... REJECT OK
2 803964124082 eni-0163e40f664bfae3d 162.216.150.164 172.31.100.171 56432 33457 6 1 44 ... REJECT OK
2 803964124082 eni-0163e40f664bfae3d 205.210.31.237 172.31.100.171 51590 993 6 1 44 ... REJECT OK
2 803964124082 eni-0163e40f664bfae3d 193.163.125.175 172.31.100.171 37383 27018 6 1 44 ... REJECT OK
2 803964124082 eni-0163e40f664bfae3d 66.132.224.27 172.31.100.171 25360 1645 17 1 48 ... REJECT OK

ACCEPT - outbound DNS/NTP queries from the instance:

2 803964124082 eni-0163e40f664bfae3d 172.31.100.171 35.176.149.124 51894 123 17 1 76 ... ACCEPT OK
2 803964124082 eni-0163e40f664bfae3d 172.31.100.171 3.8.121.220 33587 123 17 1 76 ... ACCEPT OK
2 803964124082 eni-0163e40f664bfae3d 172.31.100.171 13.40.171.61 38666 123 17 1 76 ... ACCEPT OK
2 803964124082 eni-0163e40f664bfae3d 13.40.171.61 172.31.100.171 123 38666 17 1 76 ... ACCEPT OK

NODATA - idle ENI before the instance had internet access:

2 803964124082 eni-0163e40f664bfae3d - - - - - - - ... - NODATA

## Decoding the Records

Example REJECT record:

2 803964124082 eni-0163e40f664bfae3d 205.210.31.237 172.31.100.171 51590 993 6 1 44 1791887722 1791887751 REJECT OK

| Field | Value | Meaning |
|---|---|---|
| version | 2 | Flow log format version |
| account-id | 803964124082 | Account owning the ENI |
| interface-id | eni-0163e40f664bfae3d | Instance's elastic network interface |
| srcaddr | 205.210.31.237 | External IP scanning the instance |
| dstaddr | 172.31.100.171 | Private IP of the instance |
| srcport | 51590 | Scanning tool's source port |
| dstport | 993 | IMAPS - scanned service |
| protocol | 6 | TCP |
| packets | 1 | One packet |
| bytes | 44 | Small SYN packet |
| start | 1791887722 | Epoch seconds |
| end | 1791887751 | Epoch seconds |
| action | REJECT | Blocked by SG (no inbound allow) |
| log-status | OK | Flow log record is complete |

Example ACCEPT record (outbound DNS):

2 803964124082 eni-0163e40f664bfae3d 172.31.100.171 35.176.149.124 51894 123 17 1 76 1791887754 1791887782 ACCEPT OK

| Field | Value | Meaning |
|---|---|---|
| srcaddr | 172.31.100.171 | The instance |
| dstaddr | 35.176.149.124 | AWS-provided DNS/NTP endpoint |
| srcport | 51894 | Ephemeral outbound port |
| dstport | 123 | NTP |
| protocol | 17 | UDP |
| action | ACCEPT | Allowed by SG outbound allow-all |

## Key Finding: Internet Scanning Is Constant

Within a minute of giving the instance a public IP and internet path, external hosts from multiple countries began probing common service ports:

- Port 993 (IMAPS)
- Port 33457
- Port 42567
- Port 6362
- Port 2500
- Port 27018
- Port 14141

These are automated scanners looking for open, vulnerable, or misconfigured services. Every single one was REJECT because the security group had no inbound allow rule.

This is the entire reason AWS security groups are deny-by-default. An instance with a public IP and no protection would be compromised within minutes; the SG is what turns constant background noise into a wall of REJECTs.

The ACCEPT records (outbound DNS/NTP) show the flip side: the SG's default outbound allow-all rule is what makes it possible for the instance to function at all.

## Lessons / Gotchas

1. Flow Logs are metadata-only. There is no payload, so this is not a replacement for host-based logging or IDS/IPS.

2. NODATA records are the expected state for idle ENIs. They are informative: they prove the ENI exists and that the flow log delivery pipeline is working.

3. REJECT does not mean trouble. In the sample above, all REJECTs were internet background scanning, blocked by the SG's deny-by-default. This is the system working as designed.

4. Flow logs require an IAM role with a trust policy for vpc-flow-logs.amazonaws.com and a permission policy granting logs:CreateLogStream and logs:PutLogEvents. Both are mandatory.

5. The default VPC can silently lose its internet path. In this lab, an earlier cleanup had deleted the internet gateway but the route remained, marked as blackhole. Traffic to 0.0.0.0/0 was silently dropped until the IGW was recreated and the route replaced.

6. Traffic generation is nontrivial in a private subnet. Idle instances generate NODATA; to observe real records, either deploy paired resources that talk to each other, or give the instance internet access so DNS and update traffic flow. Once given a public IP, an instance will immediately begin receiving internet background scanning.

7. Epoch timestamps matter. The start and end fields are Unix epoch seconds, not ISO timestamps. Use a small conversion step (for example, in jq or a Lambda) to correlate with CloudWatch metric timelines.

## Files

- policies/flowlogs-trust-policy.json - trust policy for vpc-flow-logs.amazonaws.com
- policies/flowlogs-permissions.json - CloudWatch Logs write permissions
- flowlog-sample.txt - raw sample of log events captured during the lab

## Real-World Application

VPC Flow Logs are foundational to network security operations:

- Incident response: when an alert fires on an EC2 instance, flow logs are the fastest way to see what it was talking to, and to what port, in the minutes before and after the alert.

- Threat hunting: scanning a week of flow logs for connections to known C2 IPs, unexpected outbound ports, or unusual data volumes.

- Compliance: PCI DSS, HIPAA, and SOC 2 often require logging of network activity to specific resources. VPC Flow Logs on the relevant ENIs is a common evidence source.

- Detection engineering: flow log records shipped to S3 can be queried with Athena, or streamed to OpenSearch/Lambda for real-time detections. A common detection is "outbound connection to a country the business does not operate in."

A classic example from this lab: REJECT records from dozens of unrelated IPs are strong evidence that the instance is exposed and being scanned, even if nothing has succeeded yet. If any of those records had shown ACCEPT, it would indicate an inbound allow rule that should not be there. This is what flow logs are for.
