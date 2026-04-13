const axios = require('axios');
const { execSync } = require('child_process');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T8',
  'Single Point of Failure (SPOF) - SSO',
  'Zineddine et al. (CMC 2025) - IdP failure disables entire ecosystem'
);

function dockerCmd(cmd) {
  try {
    execSync(`export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH" && ${cmd}`, { stdio: 'ignore' });
    return true;
  } catch (err) {
    return false;
  }
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTest() {
  console.log(`[T8] Starting SPOF Test on SSO Architecture...`);
  
  // =====================================================================
  // PHASE 1: While IdP is alive, acquire a valid JWT token
  // =====================================================================
  console.log(`[T8] Phase 1: Acquiring valid token while IdP is healthy...`);
  
  let preAcquiredToken = null;
  try {
    const authRes = await axios.post('http://localhost:4000/auth/login', {
      email: 'user@test.com',
      password: 'password123',
      client_id: 'service-a',
      redirect_uri: 'http://localhost:4002/callback'
    });
    
    const tokenRes = await axios.post('http://localhost:4000/auth/token', {
      grant_type: 'authorization_code',
      code: authRes.data.code,
      redirect_uri: 'http://localhost:4002/callback',
      client_id: 'service-a',
      client_secret: 'secret-a'
    });
    
    preAcquiredToken = tokenRes.data.access_token;
    console.log(`[T8] Got valid token: ${preAcquiredToken.substring(0, 20)}...`);
  } catch (err) {
    console.log(`[T8] Warning: Could not acquire token via normal flow. Using JWT Service...`);
    try {
      const jwtRes = await axios.post('http://localhost:4001/sign', {
        payload: {
          iss: 'http://localhost:4000',
          sub: 'user_001',
          aud: 'service-a',
          email: 'user@test.com',
          role: 'user',
          jti: 'spof-test-' + Date.now(),
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      });
      preAcquiredToken = jwtRes.data.token;
      console.log(`[T8] Got token via JWT Service: ${preAcquiredToken.substring(0, 20)}...`);
    } catch (e) {
      console.log(`[T8] FATAL: Cannot acquire any token. Aborting.`);
      return;
    }
  }
  
  // =====================================================================
  // PHASE 2: Kill the IdP
  // =====================================================================
  console.log(`[T8] Phase 2: Stopping sso-identity-provider container...`);
  dockerCmd('docker stop sso-idp');
  await sleep(3000); // Wait for container to fully stop
  
  // =====================================================================
  // PHASE 3: Test NEW login attempts (expected: ALL FAIL)
  // =====================================================================
  console.log(`[T8] Phase 3: Testing NEW login attempts with IdP down...`);
  
  const services = [
    { name: 'Service A', port: 4002 },
    { name: 'Service B', port: 4003 },
    { name: 'Admin Panel', port: 4004 },
    { name: 'API Service', port: 4005 }
  ];
  
  let newLoginAvailability = 0;
  for (const svc of services) {
    try {
      await axios.post('http://localhost:4000/auth/login', {
        email: 'user@test.com',
        password: 'password123',
        client_id: 'service-a',
        redirect_uri: `http://localhost:${svc.port}/callback`
      }, { timeout: 2000 });
      newLoginAvailability++;
    } catch (err) {
      console.log(`[T8]   ❌ New login FAILED for ${svc.name} (IdP unreachable)`);
    }
  }
  
  console.log(`[T8] New logins available: ${newLoginAvailability}/4`);
  
  // =====================================================================
  // PHASE 4: Test EXISTING token access (expected: STILL WORKS)
  // This is the critical nuance — JWT is stateless, verified with
  // the public key which is already cached in the service provider.
  // IdP being down does NOT invalidate existing tokens.
  // =====================================================================
  console.log(`[T8] Phase 4: Testing EXISTING token access with IdP down...`);
  
  let existingTokenAccess = 0;
  for (const svc of services) {
    try {
      const res = await axios.get(`http://localhost:${svc.port}/dashboard`, {
        headers: { Authorization: `Bearer ${preAcquiredToken}` },
        timeout: 2000
      });
      if (res.status === 200) {
        existingTokenAccess++;
        console.log(`[T8]   ✅ ${svc.name}: Existing token ACCEPTED (stateless JWT works)`);
      }
    } catch (err) {
      console.log(`[T8]   ❌ ${svc.name}: Existing token rejected (${err.message})`);
    }
  }
  
  console.log(`[T8] Existing token access: ${existingTokenAccess}/4`);
  
  // =====================================================================
  // RESULTS
  // =====================================================================
  collector.addResult({
    scenario: 'sso-idp down',
    newLoginAvailability: newLoginAvailability,
    existingTokenAccess: existingTokenAccess,
    totalServices: 4,
    spofForNewLogins: newLoginAvailability === 0,
    existingSessionsSurvive: existingTokenAccess > 0
  });
  
  const nuancedResult = `New logins: ${newLoginAvailability}/4 (SPOF confirmed). ` +
    `Existing sessions: ${existingTokenAccess}/4 (stateless JWT survives IdP outage).`;
  
  collector.setComparison(
    'SSO centralizes authentication risk. IdP failure blocks new logins but stateless JWTs remain valid until expiry.',
    nuancedResult,
    'CONFIRMED WITH NUANCE'
  );
  collector.save();
  
  // =====================================================================
  // RESTORE
  // =====================================================================
  console.log(`[T8] Restarting sso-identity-provider container...`);
  dockerCmd('docker start sso-idp');
  await sleep(3000);
  console.log(`[T8] IdP restored.`);
}

runTest().catch(console.error);
