# Lab 2.1 - Security Groups vs NACLs

**Date:** 2026-10-13
**Goal:** Understand the difference between stateful Security Groups and stateless Network ACLs by building both and demonstrating the classic NACL stateless-trap.

## Objective

1. Create a Security Group with an inbound HTTP rule and observe its default stateful behavior
2. Create a custom NACL and observe its default deny-all posture
3. Demonstrate the stateless trap: inbound allow without matching outbound allow breaks the response path
4. Fix the trap by adding an ephemeral-port outbound rule
5. Compare SG and NACL semantics side by side

## Concept: Stateful vs Stateless

### Security Groups (stateful)

- Attach to ENIs / instances
- Allow-only rules (no deny)
- Stateful: response to an allowed inbound request is automatically allowed outbound
- One rule per direction, but return traffic needs no rule
- Evaluated as a union of all rules

### Network ACLs (stateless)

- Attach to subnets
- Allow AND deny rules, evaluated in numbered order (first match wins)
- Stateless: each direction is evaluated independently
- You must define both inbound AND outbound rules for two-way traffic
- Default catch-all deny at rule 32767 (cannot be deleted)

### The Trap

A NACL with only an inbound HTTP allow looks correct but breaks. The server's response goes out to the client on an ephemeral port (typically 1024-65535), which hits rule 32767 deny-all outbound. The connection silently fails.

Security Groups do not have this problem because they remember the inbound connection and allow the return path automatically.

## What Was Built

### Resources created

| Resource | ID |
|---|---|
| Test security group | sg-0628553cf45107da1 |
| Test subnet | subnet-061a5fe1252d2f069 (172.31.100.0/24, eu-north-1a) |
| Custom network ACL | acl-00f12245991c65531 |
| Default network ACL (reference) | acl-0d59cb92ec796042f |
| Default VPC | vpc-0b00f49eaaa30977c (172.31.0.0/16) |

## Security Group Configuration

### Default state (immediately after creation)

Inbound: none
Outbound: allow all (rule IpProtocol -1 from 0.0.0.0/0)

### After adding HTTP inbound

Inbound:

| Protocol | Port | Source | Action |
|---|---|---|---|
| tcp | 80 | 0.0.0.0/0 | allow |

Outbound (unchanged):

| Protocol | Port | Destination | Action |
|---|---|---|---|
| -1 (all) | all | 0.0.0.0/0 | allow |

**Key observation:** the security group now allows HTTP in. Because SGs are stateful, the HTTP response to any permitted inbound request is automatically allowed out. No outbound rule needs to be added for the response.

Command used:

aws ec2 authorize-security-group-ingress --group-id sg-0628553cf45107da1 --protocol tcp --port 80 --cidr 0.0.0.0/0

## NACL Configuration

### Default NACL (baseline, for comparison)

| Rule # | Direction | Protocol | Action |
|---|---|---|---|
| 100 | in | -1 | allow |
| 100 | out | -1 | allow |
| 32767 | in | -1 | deny |
| 32767 | out | -1 | deny |

The default NACL allows everything by default. This is why people rarely notice NACLs until they create a custom one.

### Custom NACL immediately after creation

| Rule # | Direction | Protocol | Action |
|---|---|---|---|
| 32767 | in | -1 | deny |
| 32767 | out | -1 | deny |

A new NACL denies everything in both directions. Nothing gets through until explicit allows are added.

### Custom NACL after the stateless trap (inbound HTTP only)

| Rule # | Direction | Protocol | Ports | Action |
|---|---|---|---|---|
| 100 | in | tcp | 80 | allow |
| 32767 | in | -1 | all | deny |
| 32767 | out | -1 | all | deny |

This looks correct but is broken. An inbound HTTP request reaches the server. The server sends a response to the client's ephemeral port. That outbound packet matches rule 32767 (deny all). The connection fails.

### Custom NACL after the fix (inbound HTTP + outbound ephemeral)

| Rule # | Direction | Protocol | Ports | Action |
|---|---|---|---|---|
| 100 | in | tcp | 80 | allow |
| 32767 | in | -1 | all | deny |
| 100 | out | tcp | 1024-65535 | allow |
| 32767 | out | -1 | all | deny |

The outbound ephemeral range allow permits response traffic to reach the client. The connection now works end to end.

Command used:

aws ec2 create-network-acl-entry --network-acl-id acl-00f12245991c65531 --egress --rule-number 100 --protocol tcp --port-range From=1024,To=65535 --cidr-block 0.0.0.0/0 --rule-action allow

## Comparison Table

| Aspect | Security Group | Network ACL |
|---|---|---|
| Attaches to | ENI / instance | Subnet |
| Statefulness | Stateful | Stateless |
| Rule types | Allow only | Allow and Deny |
| Rule evaluation | Union (all rules considered) | Ordered (first match wins) |
| Return traffic | Automatic | Must be explicitly allowed |
| Default behavior | Deny all inbound, allow all outbound | Depends (default NACL allows all, custom NACL denies all) |
| Rule count limit | ~60 per direction | 20 per direction |
| Applies to | Chosen resources | All resources in the subnet |

## Lessons / Gotchas

1. Security Groups are stateful; Network ACLs are stateless. This single distinction drives the entire difference in how you configure them. SGs require rules for the direction you initiate; NACLs require rules for both directions of every flow.

2. Custom NACLs deny everything by default. Unlike SGs (which have an implicit deny anyway but no visible deny rules), NACLs literally start with only a deny-all entry. Every allowed flow needs two rules: inbound and outbound.

3. Rule numbers matter. NACLs evaluate in ascending order and stop at the first match. A rule at number 300 will never be reached if rule 100 already matches. This is where NACL misconfigurations usually happen.

4. The default NACL is permissive, and that is what makes NACLs invisible. If you never create a custom one, you never hit NACL problems. Problems appear the moment you try to tighten things down.

5. Two-direction thinking. When debugging a "connection refused" or "timeout" through a NACL, always check both directions. Common failing pattern: inbound allowed, outbound denied by 32767.

6. SGs cannot deny, only allow. If you need to deny a specific source, you must do it in the NACL. This is why many architectures use both: SGs for granular instance-level allows, NACLs for subnet-level denials of specific CIDRs.

## Files

- sg-snapshot.json - the security group configuration after adding inbound HTTP
- nacl-snapshot.json - the custom NACL configuration after both rules were added

## Real-World Application

In production VPC design, SGs and NACLs serve complementary roles:

- Security Groups are the primary access control mechanism. Every instance, load balancer, and database gets an SG, and the SG references other SGs (rather than CIDR ranges) to implement least-privilege networking.
- Network ACLs are typically used for one of two purposes: (a) blocking a specific malicious IP range at the subnet level, which is faster than editing every SG, or (b) isolating a subnet entirely (for example, a dedicated subnet for compliance workloads that must not reach the internet).

The classic enterprise pattern is: permissive default NACL, tight security groups. Advanced patterns layer custom NACLs for defence in depth, but the complexity is only justified for specific compliance requirements.

A very common real-world incident is exactly the trap demonstrated here: an engineer adds an inbound NACL rule for a new service (SSH, RDP, a database port) without adding the corresponding outbound ephemeral rule, and the connection fails despite the SG being correct. Knowing to check both directions is a fundamental troubleshooting skill for AWS networking.
