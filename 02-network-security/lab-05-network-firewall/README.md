# Lab 2.5 - AWS Network Firewall

**Date:** 2026-10-14
**Goal:** Understand AWS Network Firewall (managed L3-L7 inspection), its rule group types, its deployment model in a VPC, and its role in a defence-in-depth architecture. Adapted to design mode after the Network Firewall APIs were found to be SCP-blocked in this account.

## Objective

1. Learn what Network Firewall is and how it differs from Security Groups and NACLs
2. Understand the three config layers: firewall, firewall policy, rule groups
3. Design a stateful rule group that blocks malicious domains
4. Design a stateless rule group that drops suspicious source IPs
5. Write the firewall policy and deployment configuration as reproducible artifacts
6. Document the SCP blocker and the design

## Concept: What Network Firewall Is

AWS Network Firewall is a managed firewall and intrusion detection/prevention service that you deploy into a VPC. It inspects traffic at layers 3 through 7:

- L3/L4: IP, port, protocol filtering (like an advanced NACL)
- L5-L7: domain names (HTTP Host header, TLS SNI), protocol-specific inspection (Suricata-compatible rules)

It is fundamentally different from Security Groups and NACLs:

| Feature | Security Group | NACL | Network Firewall |
|---|---|---|---|
| OSI layer | L3/L4 | L3/L4 | L3-L7 |
| State | Stateful | Stateless | Stateful (with stateless option) |
| Deployment | Per-ENI | Per-subnet | Dedicated VPC subnets |
| Managed? | N/A | N/A | Fully managed by AWS |
| Central admin? | Per-SG | Per-NACL | Central firewall policy |
| Domain filtering? | No | No | Yes |
| IPS/IDS? | No | No | Yes (Suricata rules) |
| Logging? | Flow Logs only | Flow Logs only | Flow Logs + native alert/flow logs |
| Cost | Free | Free | ~$0.395/hour + per-GB |

Network Firewall is the AWS-managed equivalent of a traditional next-generation firewall (NGFW), positioned as a central inspection point in an enterprise VPC design.

## Architecture: Where the Firewall Lives

Network Firewall is deployed into dedicated subnets in a VPC. Traffic must be routed through those subnets for inspection to happen. The standard pattern:

Internet
   |
[Internet Gateway]
   |
[Public Subnet] - NAT Gateway / ALB
   |
   +--> [Firewall Subnet AZ-a] --+-- [Firewall Subnet AZ-b]
   |                             |
   |                        [Network Firewall endpoints]
   |                             |
   +--> [Private Subnet AZ-a] ---+--- [Private Subnet AZ-b]
                                     |
                                  Workloads

Every route table in the private subnets has a route that sends outbound traffic to the firewall endpoint. The firewall inspects, then forwards to the NAT or IGW as appropriate. Return traffic follows the reverse path.

Two firewall subnets (one per AZ) are the standard HA deployment. AWS creates a firewall endpoint ENI in each subnet, similar to how an Interface VPC Endpoint works.

## The Three Config Layers

### 1. Rule Groups

The actual filtering rules. Two types:

**Stateless rule groups** - evaluated per-packet. Fast but no connection awareness. Used for:
- Blocking specific IPs/CIDRs
- Blocking specific port ranges
- Rate limiting at L3/L4

**Stateful rule groups** - connection-aware. Slower but can do L7. Three sub-types:
- **Suricata-compatible rules** - the full IDS/IPS format
- **Domain list rules** - allow/deny specific domains via HTTP Host or TLS SNI
- **5-tuple rules** - traditional stateful firewall rules (src, dst, port, protocol)

### 2. Firewall Policy

Groups rule groups together and defines default actions:

- **StatelessDefaultActions** - what to do with traffic that no stateless rule matches. Usually aws:forward_to_sfe (send to the stateful engine).
- **StatelessFragmentDefaultActions** - same for fragmented packets.
- **StatefulDefaultActions** - what to do with established flows that no stateful rule matches. Usually aws:drop_established or aws:alert_established.
- **StatefulEngineOptions.RuleOrder** - STRICT_ORDER (first match wins) or DEFAULT_ACTION_ORDER (specific rules override default actions).
- **StatefulEngineOptions.StreamExceptionPolicy** - what to do when a stream cannot be fully inspected (DROP is common).

### 3. Firewall

The deployment itself. Ties a firewall policy to a VPC and subnet mappings.

- **VpcId** - the VPC to protect
- **SubnetMappings** - the dedicated firewall subnets (one per AZ for HA)
- **DeleteProtection** - prevents accidental deletion
- **FirewallPolicyChangeProtection** - prevents accidental policy changes
- **SubnetChangeProtection** - prevents accidental subnet remapping

These three protection flags are the "production mode" toggles. Enable them once the firewall is stable.

## The SCP Blocker

Listing firewalls was rejected:

User: arn:aws:iam::803964124082:user/admin-zeff is not authorized to
perform: network-firewall:ListFirewalls on resource:
arn:aws:network-firewall:eu-north-1:803964124082:*/* with an explicit
deny in a service control policy:
arn:aws:organizations::321043732798:policy/o-g4oan97ai8/service_control_policy/p-whl27g4i

This is the same SCP (p-whl27g4i) that blocks IAM CreateGroup, GuardDuty, and Access Analyzer. It has now been hit in four separate labs, making it the most impactful SCP in this account.

## Design Artifacts

### 1. Stateful rule group - block malicious domains

File: policies/block-domains-rule-group.json

{
  "RuleGroupName": "block-malicious-domains",
  "Type": "STATEFUL",
  "Capacity": 100,
  "RuleGroup": {
    "RulesSource": {
      "RulesSourceList": {
        "Targets": [
          ".malware.example.com",
          ".c2-server.example.net",
          ".phishing.example.org"
        ],
        "TargetTypes": ["HTTP_HOST", "TLS_SNI"],
        "GeneratedRulesType": "DENYLIST"
      }
    }
  },
  "Description": "Block outbound traffic to known malicious domains"
}

TargetTypes: HTTP_HOST matches the HTTP Host header; TLS_SNI matches the TLS Server Name Indication extension. This lets the firewall block domains even inside TLS connections, without decrypting them.

### 2. Stateless rule group - drop suspicious source IPs

File: policies/block-suspicious-ips-rule-group.json

{
  "RuleGroupName": "block-suspicious-ips",
  "Type": "STATELESS",
  "Capacity": 100,
  "RuleGroup": {
    "RulesSource": {
      "StatelessRulesAndCustomActions": {
        "StatelessRules": [
          {
            "RuleDefinition": {
              "MatchAttributes": {
                "Sources": [{"AddressDefinition": "203.0.113.0/24"}],
                "Destinations": [{"AddressDefinition": "0.0.0.0/0"}],
                "Protocols": [6],
                "DestinationPorts": [{"FromPort": 0, "ToPort": 65535}]
              },
              "Actions": ["aws:drop"]
            },
            "Priority": 1
          }
        ]
      }
    }
  },
  "Description": "Drop all traffic from a suspicious external CIDR"
}

This drops all TCP traffic from 203.0.113.0/24 (documentation range used as a stand-in). Stateless rules are evaluated first for speed.

### 3. Firewall policy

File: policies/firewall-policy.json

{
  "FirewallPolicyName": "lab25-firewall-policy",
  "FirewallPolicy": {
    "StatelessDefaultActions": ["aws:forward_to_sfe"],
    "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
    "StatefulRuleGroupReferences": [
      {"ResourceArn": "arn:aws:network-firewall:eu-north-1:803964124082:stateful-rulegroup/block-malicious-domains"}
    ],
    "StatelessRuleGroupReferences": [
      {"ResourceArn": "arn:aws:network-firewall:eu-north-1:803964124082:stateless-rulegroup/block-suspicious-ips", "Priority": 1}
    ],
    "StatefulDefaultActions": ["aws:drop_established"],
    "StatefulEngineOptions": {
      "RuleOrder": "STRICT_ORDER",
      "StreamExceptionPolicy": "DROP"
    }
  },
  "Description": "Lab 2.5 demo policy - blocks suspicious IPs and malicious domains"
}

The flow: stateless rules are evaluated first (drop if matched). If no stateless rule matches, traffic is forwarded to the stateful engine (aws:forward_to_sfe). There, stateful rules are evaluated. If no stateful rule matches, aws:drop_established drops established connections.

This "default deny" configuration is the standard enterprise posture. The alternative "default allow" posture would use aws:alert_established to log without blocking - used during initial deployment when you do not want to break anything.

### 4. Firewall deployment

File: policies/firewall-deployment.json

{
  "FirewallName": "lab25-firewall",
  "FirewallPolicyArn": "arn:aws:network-firewall:eu-north-1:803964124082:firewall-policy/lab25-firewall-policy",
  "VpcId": "vpc-0b00f49eaaa30977c",
  "SubnetMappings": [
    {"SubnetId": "REPLACE-WITH-FIREWALL-SUBNET-AZ-A"},
    {"SubnetId": "REPLACE-WITH-FIREWALL-SUBNET-AZ-B"}
  ],
  "DeleteProtection": false,
  "FirewallPolicyChangeProtection": false,
  "SubnetChangeProtection": false,
  "Description": "Lab 2.5 demo firewall - deployed in dedicated inspection subnets"
}

## Why a Firewall and Not Just Security Groups and NACLs

Security Groups and NACLs operate at L3/L4 and know nothing about domains, protocols, or content. They cannot answer questions like:

- "Is this outbound TLS connection going to a known malicious domain?"
- "Is this HTTP request trying to reach a C2 server?"
- "Is this DNS query for a domain on our threat intelligence list?"

Network Firewall can. It can read HTTP Host headers and TLS SNI extensions, run Suricata rules against traffic, and integrate with threat feeds.

It also centralizes control. In a large VPC with many subnets and hundreds of Security Groups, it is nearly impossible to enforce consistent outbound rules. A Network Firewall in the traffic path applies to all traffic, and its policies live in one place.

## Comparison with Third-Party Firewalls

Network Firewall is not the only option. Common alternatives:

- **Palo Alto VM-Series on EC2** - full NGFW features, but you manage the VMs
- **Fortinet FortiGate on EC2** - similar
- **Check Point CloudGuard** - similar
- **AWS Network Firewall** - managed, no VMs to maintain, limited feature depth compared to commercial NGFWs

The trade-off: Network Firewall is significantly simpler to operate and integrates with AWS IAM, CloudWatch, and Organizations. Third-party options offer deeper feature sets (application identification, user-based policies, advanced decryption) but require you to manage the underlying infrastructure and licensing.

For many workloads, Network Firewall is "good enough" and dramatically cheaper to operate.

## Lessons / Gotchas

1. Network Firewall is deployed into its own subnets in a VPC. It is not "attached" to a subnet like a NACL; it needs dedicated subnets for its endpoints, one per AZ for HA.

2. Traffic must be routed through the firewall subnets for inspection to occur. If the route tables do not send traffic through the firewall, it does nothing. This is the most common operational mistake.

3. Stateless rules are evaluated first and are cheaper. Use them for IP/port blocks. Use stateful rules for domain or protocol-level filtering.

4. Default deny is the recommended posture but not the only option. "Alert established" is the safe starting mode; it logs without blocking, letting you build an inventory of legitimate traffic before enforcing.

5. Firewall endpoints consume IPs. Each subnet hosts a firewall endpoint, using one or more IPs. Plan subnet sizing accordingly.

6. Cost scales with data volume. The per-hour charge is significant, but the per-GB processed charge dominates for high-throughput workloads.

7. Firewall is not a substitute for Security Groups. SGs continue to protect instances; the firewall protects the network path. Both serve a purpose.

8. The three protection flags (DeleteProtection, FirewallPolicyChangeProtection, SubnetChangeProtection) should be enabled once the firewall is stable. They prevent accidental deletion or destructive changes.

9. This lab hit the same SCP (p-whl27g4i) that has blocked IAM CreateGroup, GuardDuty, and Access Analyzer. Some enterprise SCPs specifically deny network security services to force centralized administration.

## Files

- policies/block-domains-rule-group.json - stateful domain blocking rule group
- policies/block-suspicious-ips-rule-group.json - stateless IP blocking rule group
- policies/firewall-policy.json - firewall policy combining both rule groups
- policies/firewall-deployment.json - firewall deployment configuration

## Real-World Application

Network Firewall is the central inspection layer in enterprise VPC designs. Common use cases:

- Data exfiltration prevention. Outbound traffic is filtered by domain; only approved destinations can be reached. Even compromised instances cannot exfiltrate data to attacker-controlled domains.

- Compliance. Frameworks such as PCI DSS require network inspection and segmentation. Network Firewall provides a managed inspection point that is easy to audit.

- IDS/IPS. Suricata-compatible rules let you detect known attack patterns and optionally block them. Alert-only for visibility, drop for enforcement.

- Central enforcement across many accounts. In an AWS Organization, Network Firewall policies can be shared and enforced centrally, so individual accounts cannot weaken their own network controls.

- Hybrid connectivity inspection. Traffic from VPN or Direct Connect into AWS can be routed through a Network Firewall for inspection before reaching workloads.

The typical enterprise pattern is: a shared inspection VPC, with Transit Gateway routing all inter-VPC and internet-bound traffic through it. The inspection VPC hosts Network Firewall subnets, and all other VPCs have routes pointing at the inspection VPC. This centralizes traffic inspection without requiring every VPC to run its own firewall.

Deployment is typically phased: start in alert-only mode, collect 30 to 90 days of traffic patterns, build the allow-list, then switch to enforcement mode. Going straight to enforcement without observation is a common source of production outages.
