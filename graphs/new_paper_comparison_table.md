# Academic Alignment & Comprehensive Test Results

| Test ID | Attack / Context | Academic Reference | Experimental Result | Validation Alignment |
|---------|------------------|--------------------|---------------------|----------------------|
| T11 | RBAC Role Escalation | Independent test | User→Admin: Denied (403). Forged admin token: Escalated (!). | **VULNERABILITY FOUND** |
| T11 | RBAC Role Escalation | Independent test | User→Admin: Denied (403). Forged admin token: Escalated (!). | **VULNERABILITY FOUND** |
| T1 | Brute Force Attack | Zineddine et al. (CMC 2025) | 4/4 endpoints successfully brute-forced (avg over 5 runs) | **CONFIRMED - Traditional architecture multiplies the attack surface** |
| T2 | Password Reuse Attack | Zineddine et al. (CMC 2025) | 4/4 traditional services compromised by 1 leaked credential. | **CONFIRMED** |
| T4 | JWT Replay & alg:none Attacks | Philippaerts et al. (RAID 2022) | Replay: Vulnerable. alg:none: Vulnerable. | **CONFIRMED VULNERABILITY** |
| T4 | JWT Replay & alg:none Attacks | Philippaerts et al. (RAID 2022) | Replay: Secure. alg:none: Secure. | **CONFIRMED MITIGATION** |
| T5 | Redirect URI Validation | Innocenti et al. (ACSAC 2023) | 3/3 attacks succeeded in insecure mode. | **CONFIRMED VULNERABILITY** |
| T5 | Redirect URI Validation | Innocenti et al. (ACSAC 2023) | 0/3 attacks succeeded in secure mode. | **CONFIRMED MITIGATION** |
| T6 | CSRF & State Parameter Validation | Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) | Session Fixation: Successful. State Omission: Accepted. | **CONFIRMED VULNERABILITY** |
| T6 | CSRF & State Parameter Validation | Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) | Session Fixation: Blocked. State Omission: Rejected. | **CONFIRMED MITIGATION** |
| T7 | Identity-Account Mismatch | Liu et al. (WWW 2021) | Account Takeover was: Successful (foreign key accepted!). | **CONFIRMED VULNERABILITY** |
| T7 | Identity-Account Mismatch | Liu et al. (WWW 2021) | Account Takeover was: Blocked (signature/issuer rejected). | **CONFIRMED MITIGATION** |
| T9 | Token Expiration Enforcement | Philippaerts et al. (RAID 2022) | Expired token: Rejected. Manipulated exp: Accepted (!). | **PARTIAL VULNERABILITY** |
| T9 | Token Expiration Enforcement | Philippaerts et al. (RAID 2022) | Expired token: Rejected. Manipulated exp: Rejected. | **CONFIRMED MITIGATION** |
| T3 | Servis İzolasyonu | Zineddine et al. (CMC 2025) | Traditional: 3/4 erişilebilir (1 servis çöküşü) | **CONFIRMED** |
| T8 | SPOF Nuance (SSO) | Zineddine et al. (CMC 2025) | Yeni Login: 0/4. Mevcut Token: 4/4 (Stateless JWT) | **CONFIRMED WITH NUANCE** |
| T10| Merkezi Darboğaz  | Zineddine et al. (CMC 2025) | SSO 1.71x daha yavaş (100 concurrent) | **CONFIRMED** |
