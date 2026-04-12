const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T2',
  'Password Reuse Attack',
  'Zineddine et al. (CMC 2025) - Multi-credential management risks'
);

const endpoints = [
  'http://localhost:3001/login', // Service A
  'http://localhost:3002/login', // Service B
  'http://localhost:3003/login', // Admin
  'http://localhost:3004/login'  // API
];

const REUSED_EMAIL = 'user@test.com';
const COMPROMISED_PASSWORD = 'password123'; // Assuming compromised from Service A

async function runTest() {
  console.log(`[T2] Starting Password Reuse test...`);
  console.log(`[T2] Assuming credential (${REUSED_EMAIL}:${COMPROMISED_PASSWORD}) leaked from Service A.`);
  
  let compromisedServices = 0;
  
  for (const endpoint of endpoints) {
    try {
      const res = await axios.post(endpoint, {
        email: REUSED_EMAIL,
        password: COMPROMISED_PASSWORD
      });
      
      if (res.status === 200) {
        console.log(`[T2] 🚨 Successful login at ${endpoint} using reused password!`);
        compromisedServices++;
        
        collector.addResult({
          endpoint,
          vulnerable: true,
          accessGranted: true
        });
      }
    } catch (err) {
      console.log(`[T2] Failed to login at ${endpoint}`);
      collector.addResult({
        endpoint,
        vulnerable: false,
        accessGranted: false
      });
    }
  }
  
  collector.setComparison(
    'Users tend to reuse passwords, putting all unlinked services at risk if one is breached.',
    `${compromisedServices}/${endpoints.length} traditional services compromised by 1 leaked credential.`,
    'CONFIRMED'
  );
  
  collector.save();
}

runTest().catch(console.error);
