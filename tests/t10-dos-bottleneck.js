const axios = require('axios');
const MetricsCollector = require('./utils/metrics-collector');

const collector = new MetricsCollector(
  'T10',
  'DoS Bottleneck - Centralization Stress Test',
  'Zineddine et al. (CMC 2025) - Centralization creates single bottleneck under load'
);

const CONCURRENT_REQUESTS = 100;

async function measureResponseTimes(url, body, concurrency) {
  const promises = [];
  const results = [];
  
  for (let i = 0; i < concurrency; i++) {
    const start = Date.now();
    const promise = axios.post(url, body, { timeout: 10000 })
      .then(res => {
        results.push({ status: res.status, timeMs: Date.now() - start, error: null });
      })
      .catch(err => {
        results.push({
          status: err.response ? err.response.status : 0,
          timeMs: Date.now() - start,
          error: err.code || err.message
        });
      });
    promises.push(promise);
  }
  
  await Promise.all(promises);
  return results;
}

function stats(arr) {
  const times = arr.map(r => r.timeMs);
  const successful = arr.filter(r => r.status >= 200 && r.status < 500);
  const failed = arr.filter(r => r.status === 0 || r.status >= 500);
  const sorted = [...times].sort((a, b) => a - b);
  
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const p50 = sorted[Math.floor(sorted.length * 0.5)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  const max = sorted[sorted.length - 1];
  
  return { mean: Math.round(mean), p50, p95, p99, max, successful: successful.length, failed: failed.length, total: arr.length };
}

async function runTest() {
  console.log(`[T10] Starting DoS Bottleneck Test — ${CONCURRENT_REQUESTS} concurrent requests`);
  
  const loginBody = {
    email: 'user@test.com',
    password: 'password123'
  };
  
  // =====================================================================
  // TEST A: Traditional System — distributed across 4 independent servers
  // Requests are round-robin'd across 4 endpoints
  // =====================================================================
  console.log(`\n[T10] === TRADITIONAL SYSTEM (Distributed Load) ===`);
  
  const tradEndpoints = [
    'http://localhost:3001/login',
    'http://localhost:3002/login',
    'http://localhost:3003/login',
    'http://localhost:3004/login'
  ];
  
  const tradPromises = [];
  const tradResults = [];
  
  for (let i = 0; i < CONCURRENT_REQUESTS; i++) {
    const endpoint = tradEndpoints[i % tradEndpoints.length]; // Round-robin
    const start = Date.now();
    const promise = axios.post(endpoint, loginBody, { timeout: 10000 })
      .then(res => {
        tradResults.push({ status: res.status, timeMs: Date.now() - start, error: null });
      })
      .catch(err => {
        tradResults.push({
          status: err.response ? err.response.status : 0,
          timeMs: Date.now() - start,
          error: err.code || err.message
        });
      });
    tradPromises.push(promise);
  }
  
  await Promise.all(tradPromises);
  const tradStats = stats(tradResults);
  
  console.log(`[T10] Traditional: mean=${tradStats.mean}ms, p50=${tradStats.p50}ms, p95=${tradStats.p95}ms, p99=${tradStats.p99}ms, max=${tradStats.max}ms`);
  console.log(`[T10] Traditional: ${tradStats.successful} successful, ${tradStats.failed} failed out of ${tradStats.total}`);
  
  // =====================================================================
  // TEST B: SSO System — ALL requests funnel through single IdP
  // This is the centralization bottleneck
  // =====================================================================
  console.log(`\n[T10] === SSO SYSTEM (Centralized Single IdP) ===`);
  
  const ssoBody = {
    email: 'user@test.com',
    password: 'password123',
    client_id: 'service-a',
    redirect_uri: 'http://localhost:4002/callback'
  };
  
  const ssoResults = await measureResponseTimes(
    'http://localhost:4000/auth/login',
    ssoBody,
    CONCURRENT_REQUESTS
  );
  const ssoStats = stats(ssoResults);
  
  console.log(`[T10] SSO IdP: mean=${ssoStats.mean}ms, p50=${ssoStats.p50}ms, p95=${ssoStats.p95}ms, p99=${ssoStats.p99}ms, max=${ssoStats.max}ms`);
  console.log(`[T10] SSO IdP: ${ssoStats.successful} successful, ${ssoStats.failed} failed out of ${ssoStats.total}`);
  
  // =====================================================================
  // COMPARISON
  // =====================================================================
  const bottleneckRatio = (ssoStats.mean / tradStats.mean).toFixed(2);
  console.log(`\n[T10] === BOTTLENECK ANALYSIS ===`);
  console.log(`[T10] SSO is ${bottleneckRatio}x slower than Traditional under ${CONCURRENT_REQUESTS} concurrent requests`);
  console.log(`[T10] Traditional p95: ${tradStats.p95}ms vs SSO p95: ${ssoStats.p95}ms`);
  
  collector.addResult({
    scenario: 'traditional_distributed',
    concurrentRequests: CONCURRENT_REQUESTS,
    meanMs: tradStats.mean,
    p50Ms: tradStats.p50,
    p95Ms: tradStats.p95,
    p99Ms: tradStats.p99,
    maxMs: tradStats.max,
    successfulRequests: tradStats.successful,
    failedRequests: tradStats.failed
  });
  
  collector.addResult({
    scenario: 'sso_centralized',
    concurrentRequests: CONCURRENT_REQUESTS,
    meanMs: ssoStats.mean,
    p50Ms: ssoStats.p50,
    p95Ms: ssoStats.p95,
    p99Ms: ssoStats.p99,
    maxMs: ssoStats.max,
    successfulRequests: ssoStats.successful,
    failedRequests: ssoStats.failed
  });
  
  collector.setComparison(
    'Zineddine et al. note that centralization creates a single bottleneck under high load, increasing denial-of-service risk.',
    `Under ${CONCURRENT_REQUESTS} concurrent requests: Traditional mean=${tradStats.mean}ms (distributed across 4 nodes) vs SSO mean=${ssoStats.mean}ms (single IdP). Bottleneck ratio: ${bottleneckRatio}x.`,
    parseFloat(bottleneckRatio) > 1.5 ? 'CONFIRMED - SSO centralizes load' : 'INCONCLUSIVE'
  );
  
  collector.save();
}

runTest().catch(console.error);
