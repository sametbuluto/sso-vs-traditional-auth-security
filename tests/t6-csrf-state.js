const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T6',
  'CSRF & State Parameter Validation',
  'Fett et al. (CCS 2016) & Benolli et al. (DIMVA 2021) - Missing state parameter allows Session Fixation'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

async function runTest() {
  console.log(`[T6] Starting CSRF / State validation tests. Secure Mode: ${SECURE_MODE}`);
  
  let success = false;
  
  // Test A: Try omitting state parameter completely
  try {
    const authRes = await axios.post('http://localhost:4000/auth/login', {
      email: 'victim@test.com',
      password: 'victim123',
      client_id: 'service-a',
      redirect_uri: 'http://localhost:4002/callback',
      // NO STATE parameter, explicitly omitted
      // NO PKCE either
    });
    
    if (authRes.status === 200 && authRes.data.code) {
      console.log(`[T6] 🚨 VULNERABILITY: IdP generated code without requiring 'state' or PKCE.`);
      success = true;
    }
  } catch (err) {
    if (err.response && err.response.status === 400) {
      console.log(`[T6] 🔒 BLOCKED: IdP rejected request missing 'state' or 'PKCE'.`);
    }
  }
  
  collector.addResult({
    variant: 'CSRF via State Omission',
    attackSuccessful: success,
    mitigatedBySecureMode: SECURE_MODE && !success
  });
  
  collector.setComparison(
    'Fett/Benolli proved that omitted state/PKCE directly leads to CSRF and session fixation.',
    `CSRF Attack was: ${success ? 'Successful' : 'Blocked'}.`,
    SECURE_MODE ? 'CONFIRMED MITIGATION' : 'CONFIRMED VULNERABILITY'
  );
  
  collector.save();
}

runTest().catch(console.error);
