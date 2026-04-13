const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T11',
  'RBAC Role Escalation',
  'Independent test - Vertical privilege escalation via role manipulation'
);

const SECURE_MODE = process.env.SECURE_MODE === 'true';

async function runTest() {
  console.log(`[T11] Starting RBAC Role Escalation tests. Secure Mode: ${SECURE_MODE}`);
  
  // =====================================================================
  // Get a legitimate USER-role token via JWT Service
  // =====================================================================
  let userToken;
  try {
    const jwtRes = await axios.post('http://localhost:4001/sign', {
      payload: {
        iss: 'http://localhost:4000',
        sub: 'user_001',
        aud: 'service-a',
        email: 'user@test.com',
        role: 'user',               // LEGITIMATE: user role
        jti: 'rbac-test-user-' + Date.now(),
        exp: Math.floor(Date.now() / 1000) + 3600
      }
    });
    userToken = jwtRes.data.token;
    console.log(`[T11] Got legitimate user-role token.`);
  } catch (e) {
    console.log(`[T11] Failed to get token. Aborting.`);
    return;
  }
  
  // =====================================================================
  // TEST A: User tries to access admin-only endpoint
  // Expected: 403 Forbidden (role 'user' not in allowedRoles ['admin'])
  // =====================================================================
  console.log(`[T11] Test A: User-role token accessing /admin endpoint...`);
  
  let userAccessAdmin = false;
  try {
    const res = await axios.get('http://localhost:4002/admin', {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    if (res.status === 200) {
      userAccessAdmin = true;
      console.log(`[T11] 🚨 VULNERABILITY: User-role accessed admin endpoint!`);
    }
  } catch (err) {
    if (err.response) {
      if (err.response.status === 403) {
        console.log(`[T11] 🔒 BLOCKED: 403 Forbidden — RBAC correctly denied user-role.`);
      } else if (err.response.status === 401) {
        console.log(`[T11] 🔒 BLOCKED: 401 Unauthorized — token verification failed first.`);
      }
    }
  }
  
  // =====================================================================
  // TEST B: Forged admin-role token (signed with legitimate key via JWT svc)
  // In insecure mode: jwt.decode() trusts it → privilege escalation
  // In secure mode: if signed with correct key, role is trusted too
  //   (RBAC checks role from decoded token regardless)
  // This tests whether the role claim can be SELF-ASSERTED
  // =====================================================================
  console.log(`[T11] Test B: Forged admin-role token accessing /admin endpoint...`);
  
  let forgedAdminToken;
  try {
    const jwtRes = await axios.post('http://localhost:4001/sign', {
      payload: {
        iss: 'http://localhost:4000',
        sub: 'user_001',
        aud: 'service-a',
        email: 'user@test.com',
        role: 'admin',              // FORGED: claiming admin role
        jti: 'rbac-test-forged-' + Date.now(),
        exp: Math.floor(Date.now() / 1000) + 3600
      }
    });
    forgedAdminToken = jwtRes.data.token;
    console.log(`[T11] Created forged admin-role token.`);
  } catch (e) {
    console.log(`[T11] Failed to forge token. Aborting Test B.`);
    return;
  }
  
  let forgedAccessAdmin = false;
  try {
    const res = await axios.get('http://localhost:4002/admin', {
      headers: { Authorization: `Bearer ${forgedAdminToken}` }
    });
    if (res.status === 200) {
      forgedAccessAdmin = true;
      console.log(`[T11] 🚨 VULNERABILITY: Forged admin token accessed admin endpoint!`);
      console.log(`[T11]    → Privilege escalation: user self-asserted admin role.`);
    }
  } catch (err) {
    if (err.response) {
      if (err.response.status === 403) {
        console.log(`[T11] 🔒 BLOCKED: 403 — Even with forged role, access denied.`);
      } else if (err.response.status === 401) {
        console.log(`[T11] 🔒 BLOCKED: 401 — Token verification caught the forgery.`);
      }
    }
  }
  
  collector.addResult({
    variant: 'User accessing admin endpoint',
    attackSuccessful: userAccessAdmin,
    expectedResult: '403 Forbidden'
  });
  
  collector.addResult({
    variant: 'Forged admin-role token',
    attackSuccessful: forgedAccessAdmin,
    mitigatedBySecureMode: SECURE_MODE && !forgedAccessAdmin
  });
  
  collector.setComparison(
    'RBAC enforcement ensures vertical privilege boundaries. Self-asserted role claims in JWT are a known attack vector if tokens are not properly validated.',
    `User→Admin: ${userAccessAdmin ? 'Escalated (!)' : 'Denied (403)'}. Forged admin token: ${forgedAccessAdmin ? 'Escalated (!)' : 'Denied'}.`,
    (userAccessAdmin || forgedAccessAdmin) ? 'VULNERABILITY FOUND' : 'RBAC ENFORCED'
  );
  
  collector.save();
}

runTest().catch(console.error);
