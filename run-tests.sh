#!/bin/bash
set -e

# Add custom path for host env just in case
export PATH="/usr/local/bin:/opt/homebrew/bin:$PATH"

echo "=============================================="
echo "    SSO vs TRADITIONAL AUTH SECURITY TESTS    "
echo "=============================================="

# 1. TRADITIONAL SYSTEM TESTS (T1, T2, T3)
echo -e "\n\n---> RUNNING TRADITIONAL SYSTEM TESTS <---"
node tests/t1-brute-force.js
node tests/t2-password-reuse.js
node tests/t3-isolation.js

# 2. SSO INSECURE MODE TESTS (T4-T8)
echo -e "\n\n---> RUNNING SSO SYSTEM TESTS (INSECURE MODE) <---"
export SECURE_MODE=false
# Ensure containers are up in insecure mode
docker compose up -d
sleep 5 # wait for servers to settle

node tests/t4-jwt-replay.js
node tests/t5-redirect-uri.js
node tests/t6-csrf-state.js
node tests/t7-identity-mismatch.js
node tests/t8-spof.js

# 3. SSO SECURE MODE TESTS (T4-T8)
echo -e "\n\n---> STOPPING SSO SURVICES & RESTARTING IN SECURE MODE <---"
docker compose down
export SECURE_MODE=true
docker compose up -d
echo "Waiting 5 seconds for secure mode services to boot..."
sleep 5

echo -e "\n\n---> RUNNING SSO SYSTEM TESTS (SECURE MODE) <---"
node tests/t4-jwt-replay.js
node tests/t5-redirect-uri.js
node tests/t6-csrf-state.js
node tests/t7-identity-mismatch.js
node tests/t8-spof.js

echo -e "\n\n=============================================="
echo "      ALL TESTS COMPLETED SUCCESSFULLY!       "
echo "=============================================="
echo "Results have been output to the tests/results/ directory."
