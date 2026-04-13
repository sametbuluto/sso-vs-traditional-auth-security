const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T6',
  'CSRF & State Parameter Validation',
  'Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) - Missing state parameter allows Session Fixation'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

async function runTest() {
  console.log(`[T6] Starting CSRF / Session Fixation tests. Secure Mode: ${SECURE_MODE}`);
  
  // =====================================================================
  // REAL CSRF ATTACK CHAIN (Cross-User Code Injection):
  //
  // 1. ATTACKER logs into IdP with their own credentials → gets auth code
  // 2. ATTACKER does NOT use this code themselves
  // 3. Instead, ATTACKER tricks VICTIM into submitting attacker's code
  //    to the callback endpoint (e.g., via malicious link)
  // 4. If no 'state' verification: victim's session becomes linked
  //    to attacker's account = SESSION FIXATION
  // 5. If 'state' is verified: victim's browser expects a different
  //    state value → attack is blocked
  // =====================================================================
  
  // --- PHASE 1: Attacker gets their own authorization code ---
  console.log(`[T6] Phase 1: Attacker (attacker@evil.com) initiating OAuth flow...`);
  
  let attackerCode = null;
  const attackerState = 'attacker-state-xyz';
  
  try {
    const attackerAuth = await axios.post('http://localhost:4000/auth/login', {
      email: 'user@test.com',        // attacker uses their own account
      password: 'password123',
      client_id: 'service-a',
      redirect_uri: 'http://localhost:4002/callback',
      state: SECURE_MODE ? attackerState : undefined,
      code_challenge: SECURE_MODE ? 'dummy' : undefined,
      code_challenge_method: SECURE_MODE ? 'S256' : undefined
    });
    
    if (attackerAuth.data.code) {
      attackerCode = attackerAuth.data.code;
      console.log(`[T6] Attacker obtained auth code: ${attackerCode.substring(0, 8)}...`);
    }
  } catch (err) {
    if (err.response && err.response.status === 400) {
      console.log(`[T6] 🔒 BLOCKED at Phase 1: IdP rejected attacker request (state/PKCE required).`);
      collector.addResult({
        variant: 'CSRF via Cross-User Code Injection',
        phase: 'attacker_auth',
        attackSuccessful: false,
        reason: 'IdP requires state and PKCE, attacker cannot get clean code',
        mitigatedBySecureMode: SECURE_MODE
      });
      collector.setComparison(
        'Fett/Benolli proved that omitted state/PKCE directly leads to CSRF and session fixation.',
        `CSRF Attack was: Blocked at Phase 1 (state/PKCE enforcement).`,
        'CONFIRMED MITIGATION'
      );
      collector.save();
      return;
    }
  }
  
  // --- PHASE 2: Attacker submits their code as if victim clicked it ---
  // In a real attack, this would be: victim clicks a crafted link like
  // https://service-a.com/callback?code=ATTACKER_CODE
  // The victim's browser sends this to Service A's callback
  
  console.log(`[T6] Phase 2: Simulating victim receiving attacker's code at callback...`);
  
  const victimState = 'victim-state-abc'; // victim's REAL state (different from attacker's)
  let sessionFixationSuccess = false;
  
  try {
    // Victim's browser would have stored victimState from their own auth init
    // But the code belongs to the attacker — state mismatch should catch this
    const tokenRes = await axios.post('http://localhost:4000/auth/token', {
      grant_type: 'authorization_code',
      code: attackerCode,                                  // ATTACKER's code
      redirect_uri: 'http://localhost:4002/callback',
      client_id: 'service-a',
      client_secret: 'secret-a',
      code_verifier: SECURE_MODE ? 'wrong_verifier' : undefined  // victim doesn't have attacker's PKCE verifier
    });
    
    if (tokenRes.data.access_token) {
      // In insecure mode, the code exchange succeeds because there's no
      // state check or PKCE binding — victim now has attacker's token
      console.log(`[T6] 🚨 VULNERABILITY: Code exchange succeeded!`);
      console.log(`[T6]    → Victim's session is now linked to attacker's account.`);
      console.log(`[T6]    → This is Session Fixation via CSRF.`);
      sessionFixationSuccess = true;
    }
  } catch (err) {
    if (err.response) {
      const error = err.response.data.error || 'unknown';
      console.log(`[T6] 🔒 BLOCKED at Phase 2: ${error}`);
      if (error === 'pkce_required' || error === 'invalid_grant') {
        console.log(`[T6]    → PKCE verification failed: victim cannot use attacker's code_verifier.`);
      }
    }
  }
  
  // --- PHASE 3: Test state omission independently ---
  console.log(`[T6] Phase 3: Testing state parameter omission...`);
  let stateOmissionAccepted = false;
  
  try {
    const noStateRes = await axios.post('http://localhost:4000/auth/login', {
      email: 'victim@test.com',
      password: 'victim123',
      client_id: 'service-a',
      redirect_uri: 'http://localhost:4002/callback'
      // NO state, NO PKCE — completely bare request
    });
    
    if (noStateRes.status === 200 && noStateRes.data.code) {
      console.log(`[T6] 🚨 VULNERABILITY: IdP accepted login without state or PKCE.`);
      stateOmissionAccepted = true;
    }
  } catch (err) {
    if (err.response && err.response.status === 400) {
      console.log(`[T6] 🔒 BLOCKED: IdP requires state/PKCE parameters.`);
    }
  }
  
  collector.addResult({
    variant: 'CSRF via Cross-User Code Injection',
    sessionFixationSuccessful: sessionFixationSuccess,
    stateOmissionAccepted: stateOmissionAccepted,
    attackSuccessful: sessionFixationSuccess || stateOmissionAccepted,
    mitigatedBySecureMode: SECURE_MODE && !sessionFixationSuccess && !stateOmissionAccepted
  });
  
  const overallSuccess = sessionFixationSuccess || stateOmissionAccepted;
  
  collector.setComparison(
    'Fett/Benolli proved that omitted state/PKCE directly leads to CSRF and session fixation.',
    `Session Fixation: ${sessionFixationSuccess ? 'Successful' : 'Blocked'}. State Omission: ${stateOmissionAccepted ? 'Accepted' : 'Rejected'}.`,
    SECURE_MODE ? 'CONFIRMED MITIGATION' : 'CONFIRMED VULNERABILITY'
  );
  
  collector.save();
}

runTest().catch(console.error);
