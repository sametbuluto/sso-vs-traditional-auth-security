# Academic Alignment & Test Results

| Test ID | Attack / Context | Academic Reference | Experimental Result | Validation Alignment |
|---------|------------------|--------------------|---------------------|----------------------|
| T1 | Brute Force Attack | Zineddine et al. (CMC 2025) | 4/4 endpoints successfully brute-forced | **CONFIRMED - Traditional architecture multiplies the attack surface** |
| T2 | Password Reuse Attack | Zineddine et al. (CMC 2025) | 4/4 traditional services compromised by 1 leaked credential. | **CONFIRMED** |
| T4 | JWT Replay & alg:none Attacks | Philippaerts et al. (RAID 2022) | Replay: Vulnerable. alg:none: Vulnerable. | **CONFIRMED VULNERABILITY** |
| T4 | JWT Replay & alg:none Attacks | Philippaerts et al. (RAID 2022) | Replay: Secure. alg:none: Secure. | **CONFIRMED MITIGATION** |
| T5 | Redirect URI Validation | Innocenti et al. (ACSAC 2023) | 3/3 attacks succeeded in insecure mode. | **CONFIRMED VULNERABILITY** |
| T5 | Redirect URI Validation | Innocenti et al. (ACSAC 2023) | 0/3 attacks succeeded in secure mode. | **CONFIRMED MITIGATION** |
| T6 | CSRF & State Parameter Validation | Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) | CSRF Attack was: Successful. | **CONFIRMED VULNERABILITY** |
| T6 | CSRF & State Parameter Validation | Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) | CSRF Attack was: Blocked. | **CONFIRMED MITIGATION** |
| T7 | Identity-Account Mismatch | Liu et al. (WWW 2021) | Account Takeover was: Successful. | **CONFIRMED VULNERABILITY** |
| T7 | Identity-Account Mismatch | Liu et al. (WWW 2021) | Account Takeover was: Blocked. | **CONFIRMED MITIGATION** |
| T3 | Servis İzolasyonu | Zineddine et al. (CMC 2025) | Traditional: 3/4 erişilebilir (1 servis çöküşünde) | **CONFIRMED** |
| T8 | SPOF - SSO | Zineddine et al. (CMC 2025) | SSO: 0/4 erişilebilir (IdP çöküşünde) | **CONFIRMED** |
