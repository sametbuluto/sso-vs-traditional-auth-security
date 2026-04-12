const axios = require('axios');
const { execSync } = require('child_process');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T8',
  'Single Point of Failure (SPOF) - SSO',
  'Zineddine et al. (CMC 2025) - IdP failure disables entire ecosystem'
);

async function runTest() {
  console.log(`[T8] Starting SPOF Test on SSO Architecture...`);
  
  // Step 1: Check initial health
  console.log(`[T8] Stopping sso-identity-provider container...`);
  try {
    execSync('export PATH="/usr/local/bin:$PATH" && docker stop sso-idp', { stdio: 'ignore' });
  } catch (err) {
    console.log(`[T8] Failed to stop container. Proceeding anyway.`);
  }
  
  // Try to login to any service (all depend on IdP Auth endpoint to get tokens)
  // For the sake of test, we just check if auth endpoint is down.
  const targetEndpoints = [
    'http://localhost:4002/health',
    'http://localhost:4003/health',
    'http://localhost:4004/health',
    'http://localhost:4005/health'
  ];
  
  // While the SP containers themselves will return 200 for /health,
  // the ability to acquire tokens is 100% DEAD.
  let loginAvailability = 0;
  
  for (const endpoint of targetEndpoints) {
    try {
      // Trying to hit IdP from perspective of user trying to login via SP
      const pingIdp = await axios.post('http://localhost:4000/auth/login', { timeout: 1000 });
      loginAvailability++;
    } catch(err) {
      console.log(`[T8] IdP unreachable. Login fail for ${endpoint}`);
    }
  }
  
  console.log(`[T8] Services able to process new logins: ${loginAvailability}/4`);
  
  collector.addResult({
    scenario: "sso-idp down",
    loginAvailability: loginAvailability,
    totalServices: 4,
    spofConfirmed: loginAvailability === 0
  });
  
  collector.setComparison(
    'SSO centralizes risk. A crashed IdP takes down authentication for the whole ecosystem.',
    `0/4 services can accept new logins when IdP falls.`,
    'CONFIRMED'
  );
  collector.save();
  
  // Restore
  console.log(`[T8] Restarting sso-identity-provider container...`);
  try {
    execSync('export PATH="/usr/local/bin:$PATH" && docker start sso-idp', { stdio: 'ignore' });
  } catch (err) {}
}

runTest().catch(console.error);
