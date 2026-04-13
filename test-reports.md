# SSO vs Traditional Authentication — Test Reports

> **Project:** Network Security Comparative Analysis
> **Author:** Samet Bulut (2021510016)
> **Date:** April 2026
> **Environment:** Docker Compose (10 microservices), Node.js, RS256 JWT
> **Tests:** 11 automated security scenarios (T1–T11)
> **Modes:** SECURE_MODE=false (Insecure) / SECURE_MODE=true (Secure)

---

## 1. Test Environment Overview

### Traditional Architecture (4 Services)
| Service | Port | Database | Auth Method |
|---------|------|----------|-------------|
| Service A | 3001 | Local db.json | Session/Password |
| Service B | 3002 | Local db.json | Session/Password |
| Admin Panel | 3003 | Local db.json | Session/Password |
| API Service | 3004 | Local db.json | Session/Password |

### SSO Architecture (6 Services)
| Service | Port | Role |
|---------|------|------|
| Identity Provider (IdP) | 4000 | Central auth, OAuth 2.0 Authorization Code Flow |
| JWT Service | 4001 | RSA key management, token signing |
| Service A (SP) | 4002 | Service Provider, RBAC middleware |
| Service B (SP) | 4003 | Service Provider, RBAC middleware |
| Admin Panel (SP) | 4004 | Service Provider, RBAC middleware |
| API Service (SP) | 4005 | Service Provider, RBAC middleware |

### Security Toggle
- `SECURE_MODE=false`: No PKCE, prefix-based URI matching, `jwt.decode()` (no signature verification), no state/issuer/audience checks
- `SECURE_MODE=true`: PKCE S256 enforced, exact URI matching, `jwt.verify()` with RS256, strict state/issuer/audience validation, JTI replay detection

---

## 2. Test Results

### T1 — Brute Force Attack (Traditional System)
**Reference:** Zineddine et al. (CMC 2025)
**Objective:** Demonstrate that independent login endpoints multiply the attack surface

**Methodology:**
- Dictionary of 50 common passwords; correct password at position 24
- 5 runs per endpoint for statistical reliability
- 4 independent endpoints tested

**Results (5-run average):**

| Endpoint | Mean Time | Std Dev | Attempts |
|----------|-----------|---------|----------|
| Service A (:3001) | 1,052ms | ±25ms | 24 |
| Service B (:3002) | 1,038ms | ±9ms | 24 |
| Admin (:3003) | 1,052ms | ±13ms | 24 |
| API (:3004) | 1,039ms | ±8ms | 24 |

**Finding:** All 4 endpoints compromised in ~1 second each. Low standard deviation (8–25ms) confirms reproducibility. Traditional architecture provides 4 separate attack vectors vs SSO's single IdP.

---

### T2 — Password Reuse Attack (Traditional System)
**Reference:** Zineddine et al. (CMC 2025)
**Objective:** Demonstrate credential leakage cascade across independent services

**Results:**
- Compromised credential: `user@test.com:password123`
- Services compromised: **4/4 (100%)**
- No cross-service anomaly detection exists

**Finding:** A single leaked password grants access to all services. In SSO, password is stored only at the IdP — a breach at one SP does not expose credentials.

---

### T3 — Service Isolation / Fault Tolerance (Traditional System)
**Reference:** Zineddine et al. (CMC 2025)
**Objective:** Demonstrate traditional system resilience to single-service failure

**Results:**
- Service A stopped via `docker stop trad-service-a`
- Surviving services: **3/3 (75% availability)**
- Service B, Admin, API continued operating normally

**Finding:** Traditional architecture's only structural advantage — no central dependency means localized failures remain localized. Directly contrasts with T8's SSO SPOF finding.

---

### T4 — JWT Replay & alg:none Attacks (SSO)
**Reference:** Philippaerts et al. (RAID 2022) — "97% of IdPs miss critical controls"

| Attack Vector | Insecure Mode | Secure Mode |
|--------------|---------------|-------------|
| Replay (same token twice) | 🚨 **Successful** — No JTI check | 🔒 **Blocked** — JTI blacklist active |
| alg:none (unsigned token) | 🚨 **Successful** — `jwt.decode()` trusts payload | 🔒 **Blocked** — `jwt.verify()` rejects non-RS256 |

**Finding:** Both attacks succeed when signature verification is absent. Single configuration change (`decode` → `verify`) eliminates both vectors entirely.

---

### T5 — Redirect URI Manipulation (SSO)
**Reference:** Innocenti et al. (ACSAC 2023) — "37.5% Path Confusion, 62.5% OPP"

| Variant | Manipulated URI | Insecure | Secure |
|---------|----------------|----------|--------|
| Path Confusion | `/callback/../evil` | 🚨 Accepted | 🔒 Rejected |
| OAuth Parameter Pollution | `/callback?redirect_uri=evil.com` | 🚨 Accepted | 🔒 Rejected |
| Wildcard/Suffix | `/callback.evil.com` | 🚨 Accepted | 🔒 Rejected |

**Insecure:** 3/3 (100%) | **Secure:** 0/3 (0%)

**Finding:** `startsWith()` prefix matching is fundamentally broken. Exact string match (`includes()`) eliminates all three categories. Innocenti's prevalence rates (37.5–62.5%) translate to 100% exploit certainty when the vulnerability exists.

---

### T6 — CSRF / Session Fixation (SSO)
**Reference:** Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021)

**Attack Chain (3 Phases):**

| Phase | Description | Insecure | Secure |
|-------|-------------|----------|--------|
| Phase 1 | Attacker obtains auth code with own credentials | ✅ Code obtained | ✅ Code obtained (state required) |
| Phase 2 | Attacker's code submitted on victim's behalf | 🚨 **Token issued!** Session Fixation | 🔒 `invalid_grant` — PKCE mismatch |
| Phase 3 | Login without state parameter | 🚨 **Accepted** | 🔒 `400 Bad Request` |

**Finding:** Without PKCE binding, an attacker can inject their authorization code into a victim's session. PKCE's code_verifier/code_challenge mechanism makes cross-user code injection cryptographically impossible.

---

### T7 — Identity-Account Mismatch (SSO)
**Reference:** Liu et al. (WWW 2021)

**Attack Setup:**
- Attacker generates their **own RSA 2048-bit key pair** (separate from system's keys)
- Signs JWT with: `iss: "http://evil-idp.com"`, `sub: "attacker_001"`, `email: "victim@test.com"`
- Both issuer AND cryptographic signature are foreign

| Mode | Result | Reason |
|------|--------|--------|
| Insecure | 🚨 **Account Takeover!** | `jwt.decode()` skips signature verification, trusts email claim |
| Secure | 🔒 **Blocked** | `jwt.verify()` rejects foreign signature before checking any claims |

**Finding:** Email-only identity linking without signature verification enables complete account takeover. Cryptographic signature verification is the first and strongest line of defense.

---

### T8 — Single Point of Failure / SPOF (SSO)
**Reference:** Zineddine et al. (CMC 2025)

**4-Phase Test:**

| Phase | Action | Result |
|-------|--------|--------|
| 1 | Acquire JWT while IdP is healthy | ✅ Token obtained |
| 2 | Kill IdP (`docker stop sso-idp`) | IdP DOWN |
| 3 | Attempt **new logins** to 4 services | ❌ **0/4 — SPOF confirmed** |
| 4 | Access services with **existing token** | ✅ **4/4 — Stateless JWT works!** |

**Critical Nuance:** SSO SPOF is not an instant total blackout. JWT tokens are stateless — they are verified locally using the cached public key. IdP outage blocks **new authentication** but does not invalidate **existing sessions** until token expiry (1 hour in our setup).

> *"The SSO SPOF risk manifests as gradual degradation rather than immediate total failure. New users cannot authenticate (0/4), but existing sessions remain functional (4/4) until token expiry."*

---

### T9 — Token Expiration Enforcement (SSO) — Independent Research
**Related:** Philippaerts et al. (RAID 2022) — Token Lifecycle

| Test | Description | Insecure | Secure |
|------|-------------|----------|--------|
| A | Expired token (exp = 1 hour ago) | 🔒 Rejected (`token_expired`) | 🔒 Rejected |
| B | Manipulated exp (attacker key, exp = year 2030) | 🚨 **Accepted!** | 🔒 Rejected (`token_verification_failed`) |

**Finding:** The RBAC middleware correctly checks `exp` in both modes (Test A always rejected). However, Test B reveals a subtle vulnerability: in insecure mode, since `jwt.decode()` doesn't verify signatures, an attacker can forge a token with any `exp` value using their own key pair and it will be trusted.

**Difference from T4:** T4 tests **replay** (reusing a valid token). T9 tests **expiry manipulation** (forging a token with extended lifetime). They are complementary attack vectors on token lifecycle.

---

### T10 — DoS Bottleneck: Centralization Stress Test — Independent Research
**Related:** Zineddine et al. (CMC 2025) — Centralization Risk

**Setup:** 100 concurrent authentication requests

| Metric | Traditional (4 Servers) | SSO (Single IdP) | Ratio |
|--------|------------------------|-------------------|-------|
| **Mean** | 376ms | 643ms | **1.71x** |
| **p50** (Median) | 387ms | 643ms | 1.66x |
| **p95** | 636ms | 1,145ms | **1.80x** |
| **p99** | 677ms | 1,191ms | 1.76x |
| **Max** | 677ms | 1,191ms | 1.76x |
| Success Rate | 100/100 | 100/100 | Equal |

**Finding:** The SSO IdP, as a single centralized authentication endpoint, processes requests 1.71x slower on average than the distributed traditional system under identical load. The tail latency (p95) degradation is even worse at 1.80x, indicating that SSO centralization creates a measurable performance bottleneck that compounds under high concurrency.

---

### T11 — RBAC Role Escalation — Independent Research

| Test | Description | Insecure | Secure |
|------|-------------|----------|--------|
| A | User-role token → `/admin` | 🔒 403 Forbidden | 🔒 403 Forbidden |
| B | Forged admin-role token → `/admin` | 🚨 **200 OK — Escalated!** | 🚨 **200 OK — Escalated!** |

**⚠️ Critical Finding: Vulnerability in BOTH Modes!**

The JWT Service (`/sign` endpoint) allows any caller to request a token with any `role` claim. Since the token is signed with the legitimate system key, Service A's RBAC middleware trusts the `role: "admin"` claim and grants access.

**Root Cause:** Role claims stored inside JWT tokens are self-asserted. If the token-issuing endpoint does not enforce role assignment from a trusted user database, privilege escalation is trivial.

**Recommended Fix:** The `/sign` endpoint should look up the user's actual role from the database rather than accepting it from the request body.

---

## 3. Comparative Analysis — Literature vs. Experimental Results

| Domain | Literature Finding | Lit. Metric | Our PoC (Insecure) | Our PoC (Secure) | Alignment |
|--------|-------------------|-------------|--------------------|-----------------|----|
| Attack Surface | Zineddine: Multi-login multiplies vectors | Theoretical (4x) | **4/4 endpoints cracked (100%)** avg 1045±15ms, n=5 | N/A | ✅ Confirmed |
| Password Reuse | Zineddine: Credential cascade risk | Expected | **4/4 services compromised (100%)** | N/A | ✅ Confirmed |
| Fault Tolerance | Zineddine: No central dependency | Expected | **3/4 alive (75%)** after single crash | N/A | ✅ Confirmed |
| JWT Replay | Philippaerts: 97% IdPs miss controls | 97% prevalence | **2/2 attacks successful (100%)** | **0/2 (0%)** | ✅ Confirmed |
| Redirect URI | Innocenti: 37.5% PathConf, 62.5% OPP | Prevalence rates | **3/3 exploits (100%)** | **0/3 (0%)** | ✅ Confirmed |
| CSRF/State | Fett/Benolli: Session Fixation risk | Formal proof | **Session Fixation achieved** | **PKCE blocked** | ✅ Confirmed |
| Identity Mismatch | Liu: Email-only linking → takeover | Case study | **Account Takeover (foreign key!)** | **Signature rejected** | ✅ Confirmed |
| SSO SPOF | Zineddine: IdP = single failure point | Theoretical | **New: 0/4, Existing: 4/4** | — | ✅ Confirmed (with nuance) |
| Token Lifecycle | Philippaerts: Lifecycle controls weak | 97% prevalence | **Expired: blocked, Manipulated: accepted** | **Both blocked** | ✅ Partial vuln |
| Centralization Load | Zineddine: SSO = bottleneck | Theoretical | **SSO 1.71x slower (p95: 1.80x)** | — | ✅ Confirmed |
| Role Escalation | Independent | — | **Forged admin: accepted** | **Forged admin: accepted** | ⚠️ Both modes vulnerable |

---

## 4. Key Observations

### What SSO Gets Right (vs Traditional)
1. **Single credential store** — password reuse cascade eliminated
2. **Centralized security controls** — one fix protects all services
3. **Cryptographic token verification** — when properly configured, eliminates replay, alg:none, identity mismatch, and URI manipulation

### What SSO Gets Wrong (Structural Risks)
1. **SPOF** — IdP failure blocks all new authentications (but existing sessions survive)
2. **Bottleneck** — Single IdP is 1.71x slower under concurrent load
3. **Self-asserted claims** — Role escalation possible if token endpoint lacks role validation

### The Security Toggle Insight
The `SECURE_MODE` flag demonstrates that **SSO security is not inherent** — it depends entirely on implementation quality. An improperly configured SSO system (no PKCE, no signature verification, prefix URI matching) is **more dangerous** than traditional multi-login because it centralizes all risk into a single exploitable point.

---

## 5. Limitations

1. **Isolated Docker network** — localhost latency (~0ms) does not reflect real-world network conditions (CDN, firewalls, packet loss)
2. **Deterministic dictionary** — Correct password position (24th) is fixed, not randomized across runs
3. **No real database** — JSON files used instead of SQL/NoSQL; injection attacks not modeled
4. **No MFA** — Multi-factor authentication not implemented; its impact on security profile not measured
5. **Single-machine deployment** — All 10 containers share CPU/memory resources, which may affect T10 DoS results
6. **Token expiry fixed at 1 hour** — Trade-off between UX and replay window not explored parametrically
