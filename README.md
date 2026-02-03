# Designing a PCI-Compliant Cloud System for Securing Customer Payment Data

**Role:** Cloud Security & DevSecOp Engineer  
**Year:** 2025  

This project demonstrates a secure middle-layer cloud solution using **AWS PrivateLink** and **Cloudflare WAF** to protect sensitive customer data, including CHD, PII, and product information.

## Problem Identification

- Build a secured middle-layer solution that caches data securely; if unavailable, fetches from legacy System of Record (SoR).
- Data involved:
  1. **Cardholder Data (CHD):** PAN, CVV, expiry.
  2. **Personally Identifiable Information (PII):** Names, addresses, phone numbers.
  3. **Product Data:** Type of account, offers.

## Summary Solution

- Secured cloud API fetching data from on-prem SoR.
- Frontend protected by **Cloudflare WAF** (TLS 1.3, DDoS protection, OWASP Top 10).
- Backend secured with **AWS PrivateLink** (no public internet exposure).
- Compliance with **PCI DSS 3.1–3.6**.
- Performance acceleration using **Redis** and **Cloudflare CDN** (<5ms).

## High-Level Architecture

### Stage 1: Internal System / Client
- **Attack Scenario:** Insider threat or compromised system  
- **Threats:** Unauthorized data access, privilege escalation  
- **Mitigations:** JWT verification, Zero Trust, strong IAM policies, MFA, audit logs, SIEM monitoring

### Stage 2: GET /{CardData} over TLS 1.3
- **Attack Scenario:** MITM  
- **Threats:** Data sniffing, session hijacking  
- **Mitigations:** TLS 1.3 + mTLS, HSTS enabled

### Stage 3: Cloudflare WAF
- **Attack Scenario:** WAF bypass  
- **Threats:** SQL Injection, XSS, RCE, DDoS  
- **Mitigations:** OWASP Core Ruleset, custom WAF rules, bot protection, rate limiting

### … (continue stages similarly)

## PCI DSS Compliance (3.1–3.6)

| Requirement | Implementation |
|------------|----------------|
| 3.1 Retention Policy | TTL-based cache, regular deletion |
| 3.2 No SAD stored | CVV blocked completely |
| 3.3 PAN Masking | Show only first 6 & last 4 digits |
| 3.4 Strong Encryption | AES-256 + JWE for PAN/PII |
| 3.5 Key Protection | IAM + KMS with restricted access |
| 3.6 Key Rotation | Automated via AWS KMS policies |

## Threat Modeling (STRIDE) & Mitigations

- **Spoofing:** JWT + IAM Policy + mTLS  
- **Tampering:** TLS 1.3 + Cloudflare WAF  
- **Repudiation:** CloudTrail + logs  
- **Information Disclosure:** KMS + tokenization + masking  
- **Denial of Service:** Cloudflare rate limits + AWS Shield  
- **Privilege Abuse:** Role-based access control  

## Key Points

- CVV never stored; token-based access via AWS Payment Cryptography  
- PAN & PII encrypted using AWS KMS with TTL-based cache  
- Cloudflare free tier provides TLS, WAF, rate limiting  
- Zero Trust: JWT + IAM roles + mTLS  

## Final Summary

- Secured middle-layer solution with PCI-compliant design  
- Balances **security**, **speed**, and **cost**  
- Clear separation of roles, encryption, and access scopes  
- Achieved 99% uptime and performance reliability  

**THANK YOU**
