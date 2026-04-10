# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

**Email:** security@linkshield.io

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Share vulnerability details publicly before a fix is released

**We will:**
- Acknowledge your report within 48 hours
- Provide a fix timeline within 7 days
- Credit you in our changelog (unless you prefer anonymity)

## Scope

We're interested in vulnerabilities affecting:
- API authentication/authorization bypass
- Data leakage (URLs, browsing history leaving the device)
- SSRF, injection, or other server-side attacks
- Extension content script security issues
- Mobile app data storage security
- Cryptographic weaknesses (E2E encryption, k-anonymity)

## Architecture Security

LinkShield's "Boring Database" architecture minimizes breach impact:

| Server stores | Device stores |
|---|---|
| Email, subscription | Full URL history |
| Device list | Privacy Audit results |
| Weekly aggregate numbers | Security Score details |
| Family membership | E2E encrypted alert content |

**If our server is breached:** attacker gets emails + subscription status. No URLs, no browsing data, no audit results.

## Security Features

- JWT validation with minimum 32-char secret
- SSRF protection (blocks private/internal IPs)
- CORS lockdown (no wildcard in production)
- Rate limiting (per-user daily + burst)
- 14 circuit breakers for external API resilience
- k-anonymity for breach checks
- AES-256-GCM for family alerts (E2E)
- Structured logging (never logs full URLs or IPs)
