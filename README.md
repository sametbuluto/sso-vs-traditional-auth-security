# SSO vs Traditional Authentication — Security Comparison

**Network Security HW2** | Samet Bulut | 2021510016 | Dokuz Eylül Üniversitesi

## Overview

This project compares Single Sign-On (SSO) and Traditional Multi-Login authentication systems from a security perspective. It validates findings from 6 academic papers through hands-on security testing.

## Architecture

```
project/
├── docker-compose.yml      ← Single file runs everything
├── sso/                    ← SSO system (IdP + 4 services)
│   ├── identity-provider/  (port 4000)
│   ├── jwt-service/        (port 4001)
│   ├── service-a/          (port 4002)
│   ├── service-b/          (port 4003)
│   ├── admin-panel/        (port 4004)
│   ├── api-service/        (port 4005)
│   ├── rbac-middleware/
│   └── keys/               (RSA key pair)
├── traditional/            ← Traditional system (4 independent services)
│   ├── service-a/          (port 3001)
│   ├── service-b/          (port 3002)
│   ├── admin-panel/        (port 3003)
│   └── api-service/        (port 3004)
├── tests/                  ← Automated test scripts
└── graphs/                 ← matplotlib visualization scripts
```

## Quick Start

```bash
# Start all services
docker-compose up --build

# Run tests (insecure mode)
SECURE_MODE=false node tests/run-all.js

# Run tests (secure mode) 
SECURE_MODE=true node tests/run-all.js

# Generate graphs
python3 graphs/generate_all.py
```

## Security Tests

| Test | Attack Type | Related Paper |
|------|-----------|---------------|
| T1 | Brute Force | Zineddine et al. (CMC 2025) |
| T2 | Password Reuse | Zineddine et al. (CMC 2025) |
| T3/T8 | SPOF / Fault Tolerance | Zineddine et al. (CMC 2025) |
| T4 | JWT Replay Attack | Philippaerts et al. (RAID 2022) |
| T4b | alg:none Attack | Philippaerts et al. (RAID 2022) |
| T5 | Redirect URI Manipulation | Innocenti et al. (ACSAC 2023) |
| T6 | CSRF / State Parameter | Fett et al. (CCS 2016), Benolli et al. (DIMVA 2021) |
| T7 | Identity-Account Mismatch | Liu et al. (WWW 2021) |

## References

1. Fett, Küsters & Schmitz — A Comprehensive Formal Security Analysis of OAuth 2.0 (CCS 2016)
2. Benolli et al. — The Full Gamut of an Attack: An Empirical Analysis of OAuth CSRF in the Wild (DIMVA 2021)
3. Innocenti et al. — OAuth 2.0 Redirect URI Validation Falls Short, Literally (ACSAC 2023)
4. Liu, Gao & Wang — An Investigation of Identity-Account Inconsistency in SSO (WWW 2021)
5. Zineddine et al. — Single Sign-On Security and Privacy: A Systematic Literature Review (CMC 2025)
6. Philippaerts et al. — OAuch: Exploring Security Compliance in the OAuth 2.0 Ecosystem (RAID 2022)
