# Lab 2.7 - Bastion vs SSM Session Manager

**Date:** 2026-10-14
**Goal:** Compare the two main patterns for administrative access to instances in private subnets, and prove the SSM Session Manager approach works end to end by executing a command on a managed instance with no SSH keys, no bastion host, and no inbound security group rules.

## Objective

1. Understand the two patterns: bastion host and SSM Session Manager
2. Build an IAM role and instance profile for SSM
3. Launch an instance, let it register with SSM, and execute a command
4. Prove the security properties: no inbound rules, no keys, no public IP required
5. Document when each approach is appropriate

## Concept: Two Access Patterns

### Bastion host (traditional)

A bastion (also called a jump host) is a small EC2 instance in a public subnet with an SSH port open to the internet or to a corporate IP range. Administrators SSH to the bastion, then SSH from the bastion to the private instances.

Characteristics:

- Requires a public subnet
- Requires an inbound SSH rule on the bastion
- Requires a key pair (often shared among administrators)
- Requires SSH agent forwarding or copies of private keys on the bastion
- Requires an inbound SSH rule on every target instance, scoped to the bastion's SG
- Auditing depends on sshd logs and shell history

### SSM Session Manager (modern)

Session Manager is a managed service that lets administrators open a shell session to an EC2 instance without SSH. The SSM agent on the instance makes an outbound HTTPS connection to the SSM service, and the administrator connects to SSM.

Characteristics:

- No public subnet required
- No inbound rules on the instance (all traffic is outbound to SSM)
- No SSH key pair
- No bastion host
- IAM controls who can start a session on which instances
- Every session is logged in CloudTrail; optional session recording to S3/CloudWatch Logs
- Port forwarding and tunneling available (equivalent to SSH -L)
- Works from the AWS Console, CLI, or SSH-like clients

## Why Session Manager Replaced Bastions

| Aspect | Bastion | Session Manager |
|---|---|---|
| Public IP required? | Yes (on bastion) | No |
| Inbound port open? | Yes (SSH 22) | No |
| SSH key management? | Yes | No |
| Access control | Key distribution + sshd config | IAM policies |
| Audit trail | Bash history / sshd logs | CloudTrail + optional session recording |
| Bastion instance cost | Yes (~$10/month) | No |
| Shell history capture | Best effort | Native |
| Just-in-time access | Manual | Via IAM policy + session duration |
| Multi-factor auth enforcement | Manual | Via IAM policy condition |

The "no inbound rules, no keys" combination is the key win. With Session Manager, there is no exposed network surface and no credential that can be lost or stolen.

## What Was Built

| Resource | ID |
|---|---|
| SSM instance role | Lab27SSMInstanceRole (arn:aws:iam::803964124082:role/Lab27SSMInstanceRole) |
| Managed policy attached | AmazonSSMManagedInstanceCore |
| Instance profile | Lab27SSMInstanceProfile |
| VPC | vpc-0b00f49eaaa30977c |
| Subnet | subnet-0c808adca911cbff7 (172.31.100.0/24, eu-north-1a) |
| Security group | sg-01b8bbf728aed4f5f (no inbound rules) |
| EC2 instance | i-02d7bb10555fa2a75 (t3.micro, Amazon Linux 2023) |
| Elastic IP | eipalloc-0c04fbddf032079e5 |
| Internet gateway | igw-01bf7e6913d670b8c |
| SSM ping status | Online |
| Last command | 29441f96-3018-4fe0-a644-cb282f510fb1 (Success) |

## Setup Steps

### 1. Create the instance trust policy

File: policies/ssm-instance-trust.json

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}

### 2. Create the instance role and attach the SSM policy

aws iam create-role --role-name Lab27SSMInstanceRole --assume-role-policy-document file://policies/ssm-instance-trust.json
aws iam attach-role-policy --role-name Lab27SSMInstanceRole --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

AmazonSSMManagedInstanceCore is an AWS-managed policy that grants the instance:
- ssm:UpdateInstanceInformation
- ssmmessages:* (the message channel for Session Manager and Run Command)
- ec2messages:* (the message channel for the SSM agent)
- logs:CreateLogStream, logs:PutLogEvents (to the SSM agent log group)

No other permissions are granted to the instance.

### 3. Create the instance profile

EC2 instances cannot assume a role directly. They need an instance profile, which is a container for the role.

aws iam create-instance-profile --instance-profile-name Lab27SSMInstanceProfile
aws iam add-role-to-instance-profile --instance-profile-name Lab27SSMInstanceProfile --role-name Lab27SSMInstanceRole

### 4. Create the security group (no inbound rules)

aws ec2 create-security-group --group-name lab27-ssm-sg --description "Lab 2.7 SSM instance" --vpc-id vpc-0b00f49eaaa30977c

The default SG allows all outbound, which is what the SSM agent needs. No inbound rules are added.

### 5. Launch the instance with the instance profile

aws ec2 run-instances --image-id ami-04c267a6ca05944f8 --instance-type t3.micro --subnet-id subnet-0c808adca911cbff7 --security-group-ids sg-01b8bbf728aed4f5f --iam-instance-profile Name=Lab27SSMInstanceProfile --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=lab27-ssm-target}]"

The default subnet has no route to the internet, so the SSM agent cannot reach the SSM service. Two things are required:

1. An internet path (either an IGW with a public IP on the instance, or VPC endpoints for SSM - see later section)
2. The route table default route pointing at a live IGW

### 6. Wait for the agent to register

aws ssm describe-instance-information

Once the instance shows PingStatus Online, it is ready.

### 7. Send a command

aws ssm send-command --instance-ids i-02d7bb10555fa2a75 --document-name "AWS-RunShellScript" --parameters "commands=hostname;whoami;uname -a" --query "Command.CommandId" --output text

Returned: 29441f96-3018-4fe0-a644-cb282f510fb1

### 8. Retrieve the output

aws ssm get-command-invocation --command-id 29441f96-3018-4fe0-a644-cb282f510fb1 --instance-id i-02d7bb10555fa2a75 --query "{Status:Status,Output:StandardOutputContent}" --output json

Output:

{
    "Status": "Success",
    "Output": "ip-172-31-100-104.eu-north-1.compute.internal\nroot\nLinux ip-172-31-100-104.eu-north-1.compute.internal 6.18.54-121.166.amzn2023.x86_64 #2 SMP PREEMPT_DYNAMIC Tue Oct  6 23:11:34 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\n"
}

This is the whole lab: a command executed as root on an instance with no SSH keys, no bastion, and zero inbound security group rules.

## The Internet-Access Problem and How Production Solves It

During this lab, the instance initially could not register with SSM because:

1. The default VPC subnet had no route to the internet (the previous IGW had been deleted)
2. A route table had a blackhole route (pointing at the deleted IGW)

Once a new IGW was created, attached, and the route was replaced, the instance registered. In production, the pattern is different: SSM connectivity is provided by **VPC Interface Endpoints**, not by giving instances public internet access.

The three Interface Endpoints required for SSM are:

- com.amazonaws.<region>.ssm
- com.amazonaws.<region>.ssmmessages
- com.amazonaws.<region>.ec2messages

With these endpoints, the SSM agent reaches the SSM service over the AWS private network. No IGW, no NAT, no public IP needed. This is what production environments do.

The lab used the IGW approach because it was faster to set up in a lab context.

## Key Security Properties Proven

1. **No inbound rules on the security group.** The SSM agent only makes outbound connections. There is no port to scan and no service listening for inbound traffic.

2. **No SSH key pair.** The instance was launched without a key. Access is controlled entirely by IAM.

3. **No bastion host.** There is no intermediate jump host to compromise, patch, or pay for.

4. **Command execution as root.** The Amazon Linux 2023 SSM agent runs as root and executes commands with full privileges. This demonstrates the full power of the access model.

5. **Full audit trail.** Every SendCommand call is logged in CloudTrail with the caller identity, target instance, command ID, and parameters.

6. **IAM-gated access.** A principal can only start a session or send a command on an instance if their identity policy allows it. The instance needs no knowledge of who its administrators are.

## Comparison with Bastion

| Property | Bastion host | SSM Session Manager |
|---|---|---|
| Public subnet | Required | Not required |
| Inbound rules on instance | Required (SSH from bastion) | Not required |
| SSH key management | Required | Not required |
| Credential exposure surface | Public IP + SSH port + key | None |
| Patch burden | Bastion host OS must be patched | Agent is managed by AWS |
| Cost | Instance + EIP + data | Free (or VPC endpoint cost if private) |
| Audit trail | Bash history, sshd logs | CloudTrail + optional session recording |
| Session port forwarding | Yes (SSH tunnels) | Yes (SSM port forwarding) |
| Session recording | Not native | Yes (S3/CloudWatch Logs) |
| MFA enforcement | Manual (sshd config) | IAM policy condition |

The only scenario where bastion is still preferred is when the target is not an EC2 instance (for example, an RDS database from outside the VPC), because SSM only works on EC2 instances and on-premises servers with the SSM agent. For those cases, SSM port forwarding through a managed instance is the modern equivalent.

## Lessons / Gotchas

1. Instance profiles and roles are distinct. An EC2 instance cannot assume a role directly; it needs an instance profile that contains the role. Both are created as separate resources.

2. The SSM agent must be able to reach the SSM service. Either give the instance internet access (IGW + public IP) or create the three SSM Interface Endpoints. In production, use VPC endpoints.

3. Amazon Linux 2023 ships with the SSM agent pre-installed. For other AMIs, the agent must be installed and the service enabled.

4. A blackhole route silently breaks connectivity. The route table had a route to 0.0.0.0/0 pointing at a deleted IGW. Packets were silently dropped. This is one of the most common "why can't the instance reach anything" causes in a lab environment.

5. The ping status shows as "Online" only after the agent has registered with the SSM service. This can take 1 to 5 minutes after boot, longer if the agent's first attempt failed.

6. send-command and start-session use different APIs. send-command runs a non-interactive command (fire and forget, retrieve output later). start-session opens an interactive shell. Both go through SSM, but they have different use cases.

7. IAM controls access to SSM, not SSH. There is no authorized_keys file to manage. A user with the right IAM policy can run commands on the instance; a user without it cannot, even if they have network access.

8. Session Manager does not replace the need for CloudTrail. Without CloudTrail enabled, SendCommand calls are not logged and the audit trail is lost.

9. Session recording is a separate configuration. By default, Session Manager records who started a session and when, but not the session content. To capture the actual commands typed in a session, you must configure session recording to S3 or CloudWatch Logs.

## Files

- policies/ssm-instance-trust.json - the EC2 assume-role trust policy
- ssm-instance.json - the SSM instance information after registration
- command-output.json - the output of the test command

## Real-World Application

SSM Session Manager is the standard for administrative access in modern AWS environments:

- **No inbound network surface.** No SSH port exposed anywhere. Attackers cannot scan for or connect to an administrative interface, because none exists.

- **IAM-gated access.** Access to production instances is controlled by IAM, not by SSH key distribution. Terminating an employee's access is a single IAM change, not a key rotation across dozens of servers.

- **Audit trail for compliance.** CloudTrail records every session and command. Session recording to S3 provides full replay capability for incident response and regulatory audits.

- **Works in private subnets.** With VPC endpoints, no instance needs a public IP for administrative access. This aligns with the principle of keeping workloads off the public internet.

- **Just-in-time access.** Combined with IAM identity center and short-lived credentials, Session Manager enables temporary access patterns: grant 15-minute access, then automatically revoke.

- **Hybrid environments.** The SSM agent runs on-premises servers too (registered via a hybrid activation). The same IAM controls and audit trail apply to non-EC2 servers.

The bastion pattern still exists in legacy architectures, especially where SSM cannot be installed (very old operating systems, third-party appliances). But new AWS architectures almost universally use SSM Session Manager, and bastions are increasingly a sign of an environment that has not yet modernized.

The three-endpoint pattern (ssm, ssmmessages, ec2messages) is the standard production replacement for giving instances internet access just for SSM. The three endpoints together cost roughly the same as one NAT Gateway per month in a small environment, but eliminate the public internet exposure entirely.
