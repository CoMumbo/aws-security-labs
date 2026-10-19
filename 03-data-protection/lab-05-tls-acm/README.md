# Lab 3.5 - TLS and ACM - Certificates, Validation, HTTPS Enforcement

**Date:** 2026-10-19
**Goal:** Understand the TLS certificate lifecycle in AWS: ACM issuance, DNS validation, and the trust chain. Because no domain was available to validate, this lab combined an ACM request (demonstrating the flow) with a hands-on self-signed certificate (demonstrating the cryptographic structure).

## Objective

1. Request an ACM certificate for a domain
2. Observe the validation failure when the domain is not controlled
3. Inspect ACM's default key/signature algorithms
4. Generate a self-signed certificate with identical cryptographic properties
5. Compare Subject vs Issuer to understand the trust chain
6. Document the full pattern for when a real domain is available

## Concept: What TLS Certificates Provide

A TLS certificate proves identity and enables encryption. It contains:

- **Public key** - used for key exchange during the handshake
- **Subject** - who the certificate is for (the domain)
- **Issuer** - who signed the certificate (the CA)
- **Validity period** - NotBefore and NotAfter
- **Subject Alternative Names (SAN)** - the domains this cert covers
- **Signature** - cryptographic proof from the CA

A browser trusts a certificate only if the entire chain from root CA to leaf is trusted. Self-signed certificates break this chain (issuer = subject), so browsers warn.

## Concept: The Trust Chain
Root CA (in OS/browser trust store)
└── Intermediate CA (signed by Root CA)
└── Leaf Certificate (signed by Intermediate - this is yours)

**For ACM certificates:**
- Root: Amazon Root CA 1-3 (pre-installed in every OS/browser)
- Intermediate: Amazon RSA 2048 M01-M03
- Leaf: your domain certificate

Browsers trust ACM certificates because the chain resolves to a trusted root.

**For self-signed certificates:**
- Root = Leaf = your certificate itself
- No chain to a trusted root
- Browsers warn by default (user must explicitly bypass)

## Concept: DNS Validation vs Email Validation

ACM supports two validation methods:

### DNS Validation (Recommended)

ACM generates a CNAME record like:
_abc123.lab35.example.com CNAME _xyz789.acm-validations.aws


You add this to your DNS zone. ACM polls DNS until the record is visible, then issues the certificate. This is the only method that supports **automatic renewal** - ACM re-validates and re-issues before expiry, no manual action required.

### Email Validation

ACM sends a validation email to admin@, administrator@, hostmaster@, postmaster@, or webmaster@ for the domain. You click the link, ACM issues the cert.

This method does NOT support auto-renewal - you must click a new validation email every 13 months. Not recommended.

### Why example.com Fails Immediately

`example.com` is a reserved domain (RFC 2606). AWS knows you cannot control DNS for it. Any ACM request for `*.example.com` returns ADDITIONAL_VERIFICATION_REQUIRED immediately. The certificate is never issued.

## What Was Built

| Resource | Value |
|---|---|
| ACM certificate request | arn:aws:acm:eu-north-1:803964124082:certificate/b1f6d571-02ab-475b-baca-5def7aec5984 |
| ACM status | FAILED |
| ACM failure reason | ADDITIONAL_VERIFICATION_REQUIRED |
| ACM key algorithm | RSA-2048 |
| ACM signature algorithm | SHA256WITHRSA |
| Self-signed cert subject | CN=lab35.local |
| Self-signed cert issuer | CN=lab35.local |
| Self-signed cert key size | 2048 bits |
| Self-signed cert signature | sha256RSA |
| Self-signed thumbprint | 73CF0481AE28943A9727DBDDB03EDEB40B2FB5B0 |

## ACM Demonstration

### Request the certificate

aws acm request-certificate --domain-name "lab35.example.com" --validation-method DNS

Returned ARN: arn:aws:acm:eu-north-1:803964124082:certificate/b1f6d571-02ab-475b-baca-5def7aec5984

### Check validation status

aws acm describe-certificate --certificate-arn arn:aws:acm:eu-north-1:803964124082:certificate/b1f6d571-02ab-475b-baca-5def7aec5984

Returned:

{
    "DomainName": "lab35.example.com",
    "ValidationDomain": "lab35.example.com",
    "ValidationStatus": "FAILED",
    "ValidationMethod": "DNS"
}

The FAILED status is immediate - not PENDING. AWS rejects example.com validation without waiting because it knows this is a reserved domain.

### Check certificate metadata

aws acm describe-certificate ... --query "Certificate.{Status:Status,FailureReason:FailureReason,Type:Type,KeyAlgorithm:KeyAlgorithm,SignatureAlgorithm:SignatureAlgorithm}"

Returned:

| Field | Value |
|---|---|
| Status | FAILED |
| FailureReason | ADDITIONAL_VERIFICATION_REQUIRED |
| Type | AMAZON_ISSUED |
| KeyAlgorithm | RSA-2048 |
| SignatureAlgorithm | SHA256WITHRSA |

The metadata is the same as a successfully issued certificate - the algorithms are already determined at request time. Only the actual issuance and trust chain depend on validation.

## Self-Signed Certificate Demonstration

### Create a self-signed certificate

```powershell
$cert = New-SelfSignedCertificate -DnsName "lab35.local" -CertStoreLocation "Cert:\CurrentUser\My" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(365)
Returned:

Field    Value
Subject    CN=lab35.local
Thumbprint    73CF0481AE28943A9727DBDDB03EDEB40B2FB5B0
NotBefore    2026-10-19
NotAfter    2027-10-19 (1 year)
Inspect the cryptographic details
powershell
$cert.SignatureAlgorithm.FriendlyName   # sha256RSA
$cert.PublicKey.Key.KeySize             # 2048
$cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
Results:

Signature: sha256RSA (same algorithm as ACM's SHA256WITHRSA)

Key size: 2048 bits (same as ACM's RSA-2048)

SAN extension: present, contains lab35.local

Compare Subject and Issuer
powershell
$cert | Format-List Subject, Issuer
Returned:

text
Subject : CN=lab35.local
Issuer  : CN=lab35.local
Subject = Issuer. This is the definition of self-signed. No chain of trust exists.

For an ACM certificate, the issuer would be CN=Amazon RSA 2048 M01, O=Amazon, C=US - a completely different entity. The chain of trust resolves to a root CA that the OS already trusts.

The Real ACM Flow (When You Have a Domain)
If you own a domain (say, mycompany.com) and have DNS access:

Step 1 - Request the certificate
aws acm request-certificate
--domain-name "app.mycompany.com"
--validation-method DNS
--subject-alternative-names "*.app.mycompany.com"
--region us-east-1

Note: for CloudFront, the certificate must be in us-east-1 (global). For ALB/API Gateway/CloudFront with a regional cert, it can be in the resource's region.

Step 2 - Get the validation record
aws acm describe-certificate --certificate-arn <ARN> --query "Certificate.DomainValidationOptions"

Returns something like:

{
"DomainName": "app.mycompany.com",
"ResourceRecord": {
"Name": "_abc123.app.mycompany.com",
"Type": "CNAME",
"Value": "_xyz789.acm-validations.aws"
},
"ValidationStatus": "PENDING_VALIDATION",
"ValidationMethod": "DNS"
}

Step 3 - Add the CNAME to DNS
Via Route 53, Cloudflare, Namecheap, GoDaddy, or any DNS provider. The exact command depends on the provider.

For Route 53, one command:
aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://cname-change.json

Step 4 - Wait for validation
ACM polls the CNAME every few minutes. Once visible, the certificate moves from PENDING_VALIDATION to ISSUED. Usually takes 5-30 minutes.

Step 5 - Attach to a resource
ALB: aws elbv2 create-listener --protocol HTTPS --certificates CertificateArn=<ARN>

API Gateway: configure custom domain with the cert

CloudFront: attach to distribution with the cert in us-east-1

Step 6 - Auto-renewal
ACM automatically re-validates and re-issues the certificate before expiration. With DNS validation, this is fully automatic. No action needed for the life of the domain.

HTTPS Enforcement Patterns
Once a certificate is attached, you need to enforce HTTPS (not just allow it). The standard patterns:

Pattern 1: HTTP → HTTPS redirect at the load balancer
ALB rule: if protocol = HTTP, then redirect to HTTPS 443.

This is a 1-line configuration on an ALB listener. No application code changes.

Pattern 2: HSTS (HTTP Strict Transport Security)
The server responds with:

text
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Browsers refuse HTTP for that domain for the duration. After the first HTTPS visit, HTTP is never attempted again - browsers rewrite the URL internally.

HSTS is configured at the server (ALB, CloudFront, or application). It's an additive header.

Pattern 3: Deny HTTP at the WAF or application
Application-level check: if request is HTTP, return 403. This is stronger than redirect but breaks bookmarks. Redirect is usually preferred.

Pattern 4: TLS-only listener on the load balancer
No HTTP listener at all. Clients connect on 443 only. Users who type "http://" will get connection refused. This is the strictest but least friendly.

Pattern 5: Security group restriction
If instances are only reachable on 443 (not 80) from the load balancer, HTTP is impossible. This is defense in depth alongside the above patterns.

TLS Versions and Cipher Suites
ALB and CloudFront support TLS 1.2 and 1.3. TLS 1.0 and 1.1 are deprecated (all major browsers refuse them since 2020). Best practice: TLS 1.2+ only.

ALB security policies define which TLS versions and cipher suites are allowed. The default is ELBSecurityPolicy-2016-08 - it allows older ciphers. The recommended modern policy is ELBSecurityPolicy-TLS13-1-2-2021-06 (TLS 1.3 + TLS 1.2 only).

This is a setting on the listener, not on the certificate. The certificate is compatible with all policies; the policy determines what the listener will negotiate.

Lessons / Gotchas
ACM certificates cannot be exported. Once issued, the private key stays in ACM. If you need the key (e.g., for on-premises servers), use ACM Private CA or a different certificate source.

ACM requires domain validation. You cannot get an ACM certificate for a domain you do not control. This is why public sites use ACM and internal services often use self-signed or private CA certs.

DNS validation is the only method that supports auto-renewal. Email validation requires manual action every 13 months. For any production domain, use DNS validation.

ACM rejects example.com immediately. The example.com reserved domain returns FAILED, not PENDING_VALIDATION - AWS does not even attempt validation.

The certificate algorithm is set at request time. Key algorithm (RSA-2048 by default; EC-256/EC-384 also available) and signature algorithm are chosen when the certificate is requested. You cannot change them after issuance.

The Subject Alternative Name (SAN) extension is what browsers check, not the Subject. Modern TLS ignores the old Subject CN. ACM automatically populates SAN for all requested domains.

The certificate region matters for CloudFront. Certificates for CloudFront distributions must be in us-east-1, regardless of where the distribution is served. Certificates for ALB/NLB/API Gateway must be in the same region as the resource. This is the most common ACM gotcha.

Attaching a certificate does not enable HTTPS. You must add an HTTPS listener (or CloudFront behavior) that references the certificate. The certificate alone does nothing.

ALB with an ACM cert is the standard pattern for public HTTPS. The ALB handles the TLS termination, and the backend can be HTTP (with a private security group). This is much simpler than terminating TLS on the backend instances.

HSTS is a one-way street. Once a browser caches an HSTS policy for a domain, it will refuse HTTP for the max-age period. If you enable HSTS with a long max-age and then need to revert to HTTP, you cannot - you have to wait for the max-age to expire, or get the domain banned (HSTS preload). Test with short max-age first (e.g., 300 seconds), increase after confidence.

Files
None - this lab's artifacts were created and deleted in the same session. The patterns and comparisons are documented above.

Cleanup
The failed ACM certificate was already cleaned up. If you created a self-signed cert, remove it:

Remove-Item "Cert:\CurrentUser\My<Thumbprint>"

For ACM certificates from real domains:
aws acm delete-certificate --certificate-arn <ARN>

Certificates that are in use by a resource (ALB, CloudFront) must be detached before deletion. ACM will refuse to delete a certificate that is attached.

Real-World Application
The Standard AWS HTTPS Stack
For a public web application:

Route 53 hosted zone for the domain

ACM certificate with DNS validation (auto-renewing)

ALB with HTTPS listener on 443, HTTP listener redirecting to HTTPS

Security groups allowing 443 from 0.0.0.0/0, 80 from 0.0.0.0/0 (for redirect)

Application behind the ALB on HTTP port 80, private security group

Optionally CloudFront in front of ALB with its own certificate (us-east-1)

This stack is the AWS reference architecture. The ACM certificate is the linchpin - it enables the HTTPS listener and the redirect.

The Internal Service Pattern
For internal microservices:

AWS Private CA (certificate authority as a service)

Certificates issued from the Private CA for internal domains (e.g., svc.internal)

Instances trust the Private CA root

mTLS between services using Private CA certificates

This is more expensive ($400/month for Private CA) but necessary for internal mTLS. ACM public certificates cannot be used for internal-only domains (validation requires public DNS).

The Multi-Domain Pattern
A single ACM certificate can cover multiple domains via SAN:

app.example.com

api.example.com

www.example.com

*.example.com (wildcard, covers all subdomains)

Wildcard certificates are 1 cert for all subdomains. Common for staging environments (staging.example.com, api-staging.example.com, etc.).

The Certificate Rotation Pattern
ACM auto-rotates DNS-validated certificates 60 days before expiry. No manual action needed. For applications that pin the certificate (rare, but some do), rotation can cause outages - modern TLS clients use SNI and accept any valid cert for the domain, so rotation is transparent.

The Bottom Line
ACM is free and auto-renewing with DNS validation

Certificates are region-scoped - CloudFront requires us-east-1

DNS validation is the only auto-renewal path

Subject Alternative Name is what matters - not Subject CN

Trust chain matters - root CA in OS trust store is required

Self-signed certs work technically but browsers warn (or refuse)

HTTPS enforcement requires explicit configuration - a cert alone does not redirect
