# Lab 2.6 - Route 53 Resolver DNS Firewall

**Date:** 2026-10-14
**Goal:** Build a working DNS Firewall rule group with AWS-managed threat lists, associate it with a VPC, and understand how DNS-level filtering adds a layer of protection that NACLs, Security Groups, and even Network Firewall cannot provide.

## Objective

1. Understand what DNS Firewall does and where it sits in the network stack
2. Create a rule group and add rules referencing AWS-managed threat lists
3. Associate the rule group with a VPC
4. Understand rule priority and block-response semantics
5. Document the DNS-Firewall-specific concepts

## Concept: What DNS Firewall Does

Route 53 Resolver DNS Firewall inspects DNS queries made from a VPC. It runs on the VPC's DNS resolver (the one at VPC-CIDR-base-plus-two), and applies allow/block rules based on domain name.

Why this matters:

- NACLs, Security Groups, and Network Firewall all operate on IP addresses or connection metadata. They cannot easily block "everything from bad-domain.com" because a domain resolves to IPs that change frequently.
- DNS Firewall operates at the DNS layer. When a client asks the resolver "where is bad-domain.com?", DNS Firewall says "blocked". The client never learns an IP, and no connection is ever attempted.
- This stops malware at the first call. Botnets rely on DNS to find their C2 servers. Blocking DNS kills the entire subsequent attack chain.

DNS Firewall is not a substitute for other controls. It is an additional layer. Its value is stopping threats before the first packet leaves the host.

## Where It Sits

Client (EC2 instance)
  |
  | 1. DNS query: "where is bad-domain.com?"
  v
VPC DNS Resolver (VPC CIDR base + 2)
  |
  | 2. Route 53 Resolver DNS Firewall inspects the query
  v
Match against rule group rules (in priority order)
  |
  +-- BLOCK rule matched -> return configured BlockResponse (NODATA / NXDOMAIN / OVERRIDE)
  +-- ALLOW rule matched -> return the real IP
  +-- No rule matched -> default: ALLOW (or as configured)

The filtering happens at the DNS resolver, before any TCP connection is established. There is no cost to the client network beyond the DNS lookup itself.

## Concepts

### Rule groups

A container for rules. Rule groups are created in one account, then associated with one or more VPCs. A VPC can have multiple rule groups associated, and they are evaluated in order of their VPC association priority.

### Rules

Each rule has:

- Priority - lower number = evaluated first. First match wins.
- Domain list - either an AWS-managed list or a custom list you define.
- Action - ALLOW, BLOCK, or ALERT.
- Block response - what the client sees if the rule blocks. Options:
  - NODATA - return "no data". Client sees an empty answer and typically fails to connect.
  - NXDOMAIN - return "domain does not exist". Client sees the domain as nonexistent.
  - OVERRIDE - return a specific domain (useful for redirecting to a sinkhole or landing page).

### AWS-managed domain lists

AWS maintains several threat intelligence lists that are updated continuously:

- AWSManagedDomainsAggregateThreatList - combined list of the others
- AWSManagedDomainsMalwareDomainList - known malware delivery domains
- AWSManagedDomainsAmazonGuardDutyThreatList - domains flagged by GuardDuty
- AWSManagedDomainsBotnetCommandandControl - known C2 servers

These cannot be inspected (listing contents is denied), but they can be referenced by rules. This is deliberate: it prevents attackers with read access from learning what is not detected.

### Block response choice

NODATA vs NXDOMAIN is a meaningful choice:

- NXDOMAIN is loud. The client knows the domain does not exist. Some malware samples treat NXDOMAIN as evidence of a blocked domain and either stop calling home or escalate to a fallback channel.
- NODATA is quieter. The client sees an empty answer but no explicit "does not exist". Some malware keeps retrying, which gives defenders more time to detect and respond.

Many organizations use NODATA for malware and NXDOMAIN for policy blocks (adult content, social media). This way the response itself signals the block category.

## What Was Built

| Resource | ID |
|---|---|
| Firewall rule group | rslvr-frg-16f3e71573344dc4 |
| Rule 1: block malware domains | priority 100, BLOCK, NODATA, using AWSManagedDomainsMalwareDomainList (rslvr-fdl-19c22a22cc624ad7) |
| Rule 2: block botnet C2 | priority 200, BLOCK, NXDOMAIN, using AWSManagedDomainsBotnetCommandandControl (rslvr-fdl-bd383ec1cede45cc) |
| VPC association | rslvr-frgassoc-401eff0340ac4381 |
| VPC | vpc-0b00f49eaaa30977c |
| Association priority | 101 |

Note: VPC association priority of 100 is reserved. Rule group associations must use 101 or higher.

## Setup Commands

### 1. List the AWS-managed domain lists

aws route53resolver list-firewall-domain-lists --query "FirewallDomainLists[].{Name:Name,Id:Id,Managed:ManagedOwnerName}" --output table

Returned:

- AWSManagedDomainsAggregateThreatList (rslvr-fdl-17764a248c141e9)
- AWSManagedDomainsMalwareDomainList (rslvr-fdl-19c22a22cc624ad7)
- AWSManagedDomainsAmazonGuardDutyThreatList (rslvr-fdl-9cfbbf8059454500)
- AWSManagedDomainsBotnetCommandandControl (rslvr-fdl-bd383ec1cede45cc)

### 2. Create the rule group

aws route53resolver create-firewall-rule-group --name lab26-dns-rules

The rule group starts empty. No cost until rules are added and it is associated with a VPC.

### 3. Add a block rule for malware domains

aws route53resolver create-firewall-rule --firewall-rule-group-id rslvr-frg-16f3e71573344dc4 --firewall-domain-list-id rslvr-fdl-19c22a22cc624ad7 --priority 100 --action BLOCK --block-response NODATA --name "block-malware-domains"

### 4. Add a block rule for botnet C2

aws route53resolver create-firewall-rule --firewall-rule-group-id rslvr-frg-16f3e71573344dc4 --firewall-domain-list-id rslvr-fdl-bd383ec1cede45cc --priority 200 --action BLOCK --block-response NXDOMAIN --name "block-botnet-c2"

### 5. Associate the rule group with the VPC

aws route53resolver associate-firewall-rule-group --firewall-rule-group-id rslvr-frg-16f3e71573344dc4 --vpc-id vpc-0b00f49eaaa30977c --priority 101 --name "lab26-vpc-association"

### 6. Verify

aws route53resolver list-firewall-rules --firewall-rule-group-id rslvr-frg-16f3e71573344dc4 --query "FirewallRules[].{Priority:Priority,Name:Name,Action:Action,Response:BlockResponse}" --output table

## Comparison with Other Filtering Layers

| Layer | Operates on | Can block by domain? | When it fires |
|---|---|---|---|
| Security Group | IP/port/protocol | No | On connection attempt |
| NACL | IP/port/protocol | No | Per packet |
| Network Firewall | IP/port/domain/protocol (L3-L7) | Yes (HTTP_HOST, TLS_SNI) | On packet |
| Route 53 Resolver DNS Firewall | DNS domain name only | Yes | On DNS lookup |

DNS Firewall is the earliest possible interception point. The only thing that happens before a DNS lookup is the user typing a URL - and even that triggers a DNS query. It is the first network-layer control that can act on the user's intent.

Network Firewall operates on packets after the DNS lookup has resolved a domain to an IP. It can also block by domain (via HTTP Host or TLS SNI), but the DNS lookup has already succeeded by the time Network Firewall sees the packet. So DNS Firewall acts earlier.

The two are complementary: DNS Firewall stops the client from learning where bad-domain.com lives; Network Firewall stops the client from reaching IP 203.0.113.5 even if DNS was already resolved.

## Lessons / Gotchas

1. DNS Firewall blocks DNS queries, not connections. A client that has already cached a malicious IP in its local DNS cache will still connect. Cache poisoning at the resolver level is not covered; DNS Firewall only sees fresh queries.

2. Domain lists are updated by AWS continuously. This is the main reason to use the AWS-managed lists instead of your own - you do not need to maintain a threat feed.

3. AWS-managed list contents are not readable. Listing the domains in AWSManagedDomainsMalwareDomainList returns AccessDenied. This is by design.

4. Block response choice matters. NXDOMAIN is loud (malware learns it is blocked); NODATA is quiet (malware keeps retrying). Different responses for different threat categories is a common production pattern.

5. VPC association priority 100 is reserved. Use 101 or higher for rule group associations.

6. Multiple rule groups can be associated with a VPC. They are evaluated in priority order. A common pattern is: a shared "baseline" rule group associated at priority 101, then an account-specific rule group at priority 200.

7. DNS Firewall is not the same as DNSSEC or DNS over HTTPS. It operates inside the VPC resolver, independent of how the client chooses to encrypt DNS traffic (unless the client bypasses the VPC resolver entirely with DoH to a public resolver - in which case DNS Firewall sees nothing).

8. Custom domain lists are possible. You can upload your own list of domains to block or allow, and reference it in a rule. Useful for organization-specific policies.

9. No charge for rule groups that are not associated with a VPC. Costs begin when the rule group is associated and queries are processed.

## Files

- rules.json - the two firewall rules as returned by the API
- association.json - the VPC association details
- rule-groups.json - the rule group metadata

## Real-World Application

Route 53 Resolver DNS Firewall is a standard component in enterprise VPC security designs:

- Malware C2 blocking. When an EC2 instance is compromised and tries to resolve its C2 domain, DNS Firewall returns NODATA and the connection is never attempted. This is often the single most effective control against commodity malware.

- Ransomware kill chain disruption. Ransomware often resolves a unique domain per victim for exfiltration. DNS Firewall on the GuardDuty threat list catches many of these.

- Enforcing acceptable use policies. Block access to gambling, adult content, or unauthorized SaaS at the DNS layer. Cheaper and more reliable than per-workload filtering.

- Reducing Network Firewall load. By blocking known-bad domains at the DNS layer, the more expensive Network Firewall sees less traffic.

- Compliance. Some frameworks require "DNS-layer security controls". DNS Firewall is the AWS-native way to satisfy this.

A typical enterprise pattern: a shared "baseline" rule group referencing the AWS-managed malware and botnet lists is associated with every VPC in the organization. Individual teams can add their own rule groups on top. The baseline rule group is never modified per-team, so a compromise in one team's account cannot disable the baseline protection.

DNS Firewall logs can be sent to CloudWatch Logs, S3, or Kinesis Data Firehose. A common detection engineering pattern queries these logs for blocked domains, and alerts on high volumes or unusual patterns (which could indicate a compromised host actively trying to reach C2).
