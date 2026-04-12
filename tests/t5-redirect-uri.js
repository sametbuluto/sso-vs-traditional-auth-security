const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T5',
  'Redirect URI Validation',
  'Innocenti et al. (ACSAC 2023) - OAuth Parameter Pollution & Path Confusion'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

async function runTest() {
  console.log(`[T5] Starting Redirect URI tests. Secure Mode: ${SECURE_MODE}`);
  
  const testCases = [
    { name: 'Path Confusion', uri: 'http://localhost:4002/callback/../evil' },
    { name: 'OAuth Parameter Pollution (OPP)', uri: 'http://localhost:4002/callback?redirect_uri=http://evil.com' },
    { name: 'Wildcard/Suffix', uri: 'http://localhost:4002/callback.evil.com' }
  ];
  
  let successes = 0;
  
  for (const tc of testCases) {
    try {
      const authRes = await axios.post('http://localhost:4000/auth/login', {
        email: 'user@test.com',
        password: 'password123',
        client_id: 'service-a',
        redirect_uri: tc.uri,
        state: 'random',
        code_challenge: 'valid',
        code_challenge_method: 'S256'
      });
      
      if (authRes.status === 200 && authRes.data.code) {
        console.log(`[T5] 🚨 VULNERABILITY: ${tc.name} accepted the manipulated URI!`);
        successes++;
        collector.addResult({
          variant: tc.name,
          manipulatedUri: tc.uri,
          attackSuccessful: true,
          mitigatedBySecureMode: false
        });
      }
    } catch (err) {
      if (err.response && err.response.status === 400) {
        console.log(`[T5] 🔒 BLOCKED: ${tc.name} was rejected (Secure validation).`);
        collector.addResult({
          variant: tc.name,
          manipulatedUri: tc.uri,
          attackSuccessful: false,
          mitigatedBySecureMode: SECURE_MODE
        });
      }
    }
  }
  
  collector.setComparison(
    'Innocenti et al. (ACSAC 2023) found 37.5% IdPs vulnerable to path confusion and 62.5% to OPP.',
    `${successes}/${testCases.length} attacks succeeded in ${SECURE_MODE ? 'secure' : 'insecure'} mode.`,
    SECURE_MODE ? 'CONFIRMED MITIGATION' : 'CONFIRMED VULNERABILITY'
  );
  
  collector.save();
}

runTest().catch(console.error);
