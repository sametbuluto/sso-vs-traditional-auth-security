# Quantitative Impact Analysis: Literature Findings vs. Experimental Setup

| Vulnerability Domain | Academic Study (Theoretical/Prevalence) | Empirical Vulnerability Rate (Insecure PoC) | Empirical Mitigation Rate (Secure PoC) |
|---------|--------------------|---------------------|----------------------|
| Multi-Login Attack Surface | Zineddine et al. (Multiplier effect expected) | **4/4 (100%)** endpoints compromised in ~1080ms | N/A (Architectural traditional flaw) |
| SSO Base SPOF (Reliability) | Zineddine et al. (100% ecosystem failure on IdP outage) | **0/4 (0%)** availability (SSO Ecosystem dead) | **3/4 (75%)** survival (Traditional Architecture) |
| JWT Replay & alg:none | Philippaerts et al. (97% of IdPs miss critical controls) | **2/2 (100%)** bypasses successful | **0/2 (100%)** attacks mitigated (RS256/JTI active) |
| Redirect URI Validation | Innocenti et al. (37.5% Path Confusion, 62.5% OPP) | **3/3 (100%)** exploits executed (Prefix logic flaw) | **0/3 (100%)** attacks mitigated (Exact-Match active) |
| State/PKCE Omission (CSRF) | Fett et al. & Benolli et al. (Session Fixation Risk) | **1/1 (100%)** unauthorized access granted | **0/1 (100%)** attacks mitigated (Request dropped) |
| Identity & Issuer Mismatch | Liu et al. (Sub/Iss mismatch Account Takeover Risk) | **1/1 (100%)** Fake IdP credential accepted | **0/1 (100%)** attacks mitigated (Aud/Iss valid) |
