const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T9',
  'Token Expiration Enforcement',
  'Philippaerts et al. (RAID 2022) - Token Lifecycle Management'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

// We use the attacker key to sign expired tokens independently
// But for this test, we also test with legitimately-signed expired tokens
// to check if the RBAC middleware enforces exp correctly
const ATTACKER_KEY = fs.readFileSync(path.join(__dirname, 'attacker_private.pem'), 'utf8');

async function runTest() {
  console.log(`[T9] Starting Token Expiration tests. Secure Mode: ${SECURE_MODE}`);
  
  // =====================================================================
  // TEST A: Expired token (exp in the past)
  // The RBAC middleware checks: decoded.exp < Math.floor(Date.now()/1000)
  // This should be rejected in BOTH modes.
  // =====================================================================
  console.log(`[T9] Test A: Sending token with exp set 1 hour in the PAST...`);
  
  let expiredToken;
  try {
    const jwtRes = await axios.post('http://localhost:4001/sign', {
      payload: {
        iss: 'http://localhost:4000',
        sub: 'user_001',
        aud: 'service-a',
        email: 'user@test.com',
        role: 'user',
        jti: 'expired-test-' + Date.now(),
        exp: Math.floor(Date.now() / 1000) - 3600  // 1 HOUR AGO
      }
    });
    expiredToken = jwtRes.data.token;
  } catch (e) {
    console.log(`[T9] Could not get token from JWT Service. Aborting.`);
    return;
  }
  
  let expiredAccepted = false;
  try {
    const res = await axios.get('http://localhost:4002/dashboard', {
      headers: { Authorization: `Bearer ${expiredToken}` }
    });
    if (res.status === 200) {
      expiredAccepted = true;
      console.log(`[T9] 🚨 VULNERABILITY: Expired token was ACCEPTED!`);
    }
  } catch (err) {
    if (err.response && err.response.status === 401) {
      const reason = err.response.data.error || 'unknown';
      console.log(`[T9] 🔒 BLOCKED: Expired token rejected. Reason: ${reason}`);
    }
  }
  
  // =====================================================================
  // TEST B: Token with manipulated exp (set far in the future)
  // Attacker takes a legitimately structured token but changes exp
  // to extend its validity. Signed with attacker's own key.
  // In insecure mode: jwt.decode() doesn't check signature,
  //   so manipulated exp is trusted.
  // In secure mode: jwt.verify() rejects the foreign signature first.
  // =====================================================================
  console.log(`[T9] Test B: Sending token with exp manipulated to year 2030...`);
  
  const manipulatedToken = jwt.sign(
    {
      iss: 'http://localhost:4000',
      sub: 'user_001',
      aud: 'service-a',
      email: 'user@test.com',
      role: 'admin',  // also trying privilege escalation
      jti: 'manipulated-exp-' + Date.now(),
      exp: Math.floor(new Date('2030-01-01').getTime() / 1000) // Far future
    },
    ATTACKER_KEY,
    { algorithm: 'RS256' }
  );
  
  let manipulatedAccepted = false;
  try {
    const res = await axios.get('http://localhost:4002/dashboard', {
      headers: { Authorization: `Bearer ${manipulatedToken}` }
    });
    if (res.status === 200) {
      manipulatedAccepted = true;
      console.log(`[T9] 🚨 VULNERABILITY: Manipulated-exp token ACCEPTED (foreign key, exp=2030)!`);
    }
  } catch (err) {
    if (err.response && err.response.status === 401) {
      const reason = err.response.data.error || 'unknown';
      console.log(`[T9] 🔒 BLOCKED: Manipulated token rejected. Reason: ${reason}`);
    }
  }
  
  collector.addResult({
    variant: 'Expired Token (1h past)',
    attackSuccessful: expiredAccepted,
    mitigatedBySecureMode: !expiredAccepted
  });
  
  collector.addResult({
    variant: 'Manipulated Exp (foreign key, exp=2030)',
    attackSuccessful: manipulatedAccepted,
    mitigatedBySecureMode: SECURE_MODE && !manipulatedAccepted
  });
  
  collector.setComparison(
    'Philippaerts et al. found that token lifecycle (expiry, refresh) controls are often missing or misconfigured.',
    `Expired token: ${expiredAccepted ? 'Accepted (!)' : 'Rejected'}. Manipulated exp: ${manipulatedAccepted ? 'Accepted (!)' : 'Rejected'}.`,
    (expiredAccepted || manipulatedAccepted) ? 'PARTIAL VULNERABILITY' : 'CONFIRMED MITIGATION'
  );
  
  collector.save();
}

runTest().catch(console.error);
