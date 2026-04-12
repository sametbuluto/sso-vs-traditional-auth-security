const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 4000;

// --- Configuration ---
const SECURE_MODE = process.env.SECURE_MODE === 'true';
console.log(`[IdP] SECURE_MODE: ${SECURE_MODE}`);

// --- Keys ---
const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');

// --- Middleware ---
app.use(express.json());
app.use(cors());
app.use(morgan('combined'));

// --- In-Memory Stores ---
let authorizationCodes = {}; // code -> { clientId, redirectUri, userId, scope, codeChallenge, codeChallengeMethod, state, expiresAt }
let usedJtiTokens = new Set(); // for replay attack prevention
let revokedTokens = new Set(); // for token revocation

// --- Registered Clients ---
const clients = [
  {
    client_id: 'service-a',
    client_secret: 'secret-a',
    redirect_uris: ['http://localhost:4002/callback']
  },
  {
    client_id: 'service-b',
    client_secret: 'secret-b',
    redirect_uris: ['http://localhost:4003/callback']
  },
  {
    client_id: 'admin-panel',
    client_secret: 'secret-admin',
    redirect_uris: ['http://localhost:4004/callback']
  },
  {
    client_id: 'api-service',
    client_secret: 'secret-api',
    redirect_uris: ['http://localhost:4005/callback']
  }
];

// --- Users Database ---
const PASSWORDS = {
  'user@test.com': 'password123',
  'admin@test.com': 'adminpass',
  'victim@test.com': 'victim123'
};

let users = [];

async function initUsers() {
  users = [];
  for (const [email, plainPass] of Object.entries(PASSWORDS)) {
    const hash = await bcrypt.hash(plainPass, 10);
    const id = email.split('@')[0] + '_001';
    const role = email.includes('admin') ? 'admin' : 'user';
    users.push({ id, email, password: hash, role, name: email.split('@')[0] });
  }
  console.log(`[IdP] ${users.length} users initialized`);
}

// --- Helper Functions ---
function findClient(clientId) {
  return clients.find(c => c.client_id === clientId);
}

function findUser(email) {
  return users.find(u => u.email === email);
}

function validateRedirectUri(client, redirectUri) {
  if (SECURE_MODE) {
    // SECURE: Exact string match (prevents path confusion & OPP)
    return client.redirect_uris.includes(redirectUri);
  } else {
    // INSECURE: Only checks if the redirect_uri starts with a registered URI
    // This is vulnerable to path confusion and OPP attacks
    return client.redirect_uris.some(uri => redirectUri.startsWith(uri.split('?')[0].split('#')[0]));
  }
}

function generatePKCEChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ============================================================
// ENDPOINTS
// ============================================================

// --- Health Check ---
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'identity-provider', secureMode: SECURE_MODE, timestamp: new Date().toISOString() });
});

// --- OIDC Discovery ---
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: 'http://localhost:4000',
    authorization_endpoint: 'http://localhost:4000/auth/authorize',
    token_endpoint: 'http://localhost:4000/auth/token',
    userinfo_endpoint: 'http://localhost:4000/auth/userinfo',
    revocation_endpoint: 'http://localhost:4000/auth/revoke',
    jwks_uri: 'http://localhost:4000/.well-known/jwks.json',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email']
  });
});

// --- JWKS Endpoint ---
app.get('/.well-known/jwks.json', (req, res) => {
  // Serve public key in JWK format (simplified)
  res.json({
    keys: [{
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: 'key-1',
      // In production, this would be the actual JWK representation
      pem: PUBLIC_KEY
    }]
  });
});

// --- Authorization Endpoint (OAuth 2.0) ---
// GET /auth/authorize?client_id=...&redirect_uri=...&response_type=code&state=...&code_challenge=...&code_challenge_method=S256
app.get('/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, state, scope, code_challenge, code_challenge_method } = req.query;

  // Validate client
  const client = findClient(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', message: 'Unknown client_id' });
  }

  // Validate response_type
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type', message: 'Only "code" is supported' });
  }

  // Validate redirect_uri
  if (!validateRedirectUri(client, redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri', message: 'Redirect URI not registered' });
  }

  // SECURE MODE: Validate state parameter
  if (SECURE_MODE) {
    if (!state) {
      return res.status(400).json({ error: 'missing_state', message: 'State parameter is required in secure mode' });
    }
    // SECURE MODE: Require PKCE
    if (!code_challenge || code_challenge_method !== 'S256') {
      return res.status(400).json({ error: 'pkce_required', message: 'PKCE (S256) is required in secure mode' });
    }
  }

  // For simplicity, return an authorization page URL (in real flow, user would login here)
  // In our test setup, we'll use POST /auth/login to get the code directly
  res.json({
    message: 'Authorization request accepted. Use POST /auth/login with credentials to get authorization code.',
    client_id,
    redirect_uri,
    state: state || null,
    pkce_required: SECURE_MODE
  });
});

// --- Login & Issue Authorization Code ---
// POST /auth/login
// Body: { email, password, client_id, redirect_uri, state, code_challenge, code_challenge_method }
app.post('/auth/login', async (req, res) => {
  const { email, password, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.body;

  // Validate client
  const client = findClient(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', message: 'Unknown client_id' });
  }

  // Validate redirect_uri
  if (!validateRedirectUri(client, redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri', message: 'Redirect URI not registered' });
  }

  // SECURE MODE: Validate state
  if (SECURE_MODE && !state) {
    return res.status(400).json({ error: 'missing_state', message: 'State parameter required' });
  }

  // Authenticate user
  const user = findUser(email);
  if (!user) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
  }

  // Generate authorization code
  const code = uuidv4();
  authorizationCodes[code] = {
    clientId: client_id,
    redirectUri: redirect_uri,
    userId: user.id,
    userEmail: user.email,
    userRole: user.role,
    scope: 'openid profile email',
    state: state || null,
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || null,
    expiresAt: Date.now() + 600000, // 10 minutes
    used: false
  };

  res.json({
    code,
    state: state || null,
    redirect_uri,
    message: 'Authorization code issued. Exchange it at POST /auth/token'
  });
});

// --- Token Endpoint ---
// POST /auth/token
// Body: { grant_type, code, redirect_uri, client_id, client_secret, code_verifier }
app.post('/auth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  // Validate authorization code
  const authCode = authorizationCodes[code];
  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Invalid or expired authorization code' });
  }

  // Check expiry
  if (Date.now() > authCode.expiresAt) {
    delete authorizationCodes[code];
    return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code expired' });
  }

  // Check if code was already used
  if (authCode.used) {
    delete authorizationCodes[code];
    return res.status(400).json({ error: 'invalid_grant', message: 'Authorization code already used' });
  }

  // Validate client
  const client = findClient(client_id);
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client', message: 'Client authentication failed' });
  }

  // Validate redirect_uri matches
  if (authCode.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Redirect URI mismatch' });
  }

  // Validate client_id matches
  if (authCode.clientId !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Client ID mismatch' });
  }

  // SECURE MODE: Validate PKCE code_verifier
  if (SECURE_MODE) {
    if (!code_verifier) {
      return res.status(400).json({ error: 'pkce_required', message: 'code_verifier is required' });
    }
    const expectedChallenge = generatePKCEChallenge(code_verifier);
    if (expectedChallenge !== authCode.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant', message: 'PKCE verification failed' });
    }
  }

  // Mark code as used
  authCode.used = true;

  // Find user
  const user = users.find(u => u.id === authCode.userId);
  if (!user) {
    return res.status(500).json({ error: 'server_error', message: 'User not found' });
  }

  // Generate JWT
  const jti = uuidv4();
  const now = Math.floor(Date.now() / 1000);

  const tokenPayload = {
    iss: 'http://localhost:4000',
    sub: user.id,
    aud: client_id,
    exp: now + 3600, // 1 hour
    iat: now,
    email: user.email,
    role: user.role,
    name: user.name,
    jti: jti
  };

  let accessToken;
  if (SECURE_MODE) {
    // SECURE: Sign with RS256
    accessToken = jwt.sign(tokenPayload, PRIVATE_KEY, { algorithm: 'RS256' });
  } else {
    // INSECURE: Still sign with RS256, but the validation side may accept alg:none
    accessToken = jwt.sign(tokenPayload, PRIVATE_KEY, { algorithm: 'RS256' });
  }

  // Generate ID Token (same as access token in this simplified setup)
  const idToken = jwt.sign(tokenPayload, PRIVATE_KEY, { algorithm: 'RS256' });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
    scope: authCode.scope
  });
});

// --- UserInfo Endpoint ---
app.get('/auth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token', message: 'Bearer token required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    let decoded;
    if (SECURE_MODE) {
      // SECURE: Verify with RS256 only, check all claims
      decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

      // Check if token has been revoked
      if (revokedTokens.has(decoded.jti)) {
        return res.status(401).json({ error: 'token_revoked', message: 'Token has been revoked' });
      }

      // Check jti for replay (optional for userinfo, but good practice)
    } else {
      // INSECURE: Accept any algorithm (vulnerable to alg:none)
      decoded = jwt.decode(token, { complete: false });
      if (!decoded) {
        return res.status(401).json({ error: 'invalid_token', message: 'Failed to decode token' });
      }
    }

    // Validate issuer in secure mode
    if (SECURE_MODE && decoded.iss !== 'http://localhost:4000') {
      return res.status(401).json({ error: 'invalid_issuer', message: 'Token issuer mismatch' });
    }

    res.json({
      sub: decoded.sub,
      email: decoded.email,
      role: decoded.role,
      name: decoded.name
    });
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token', message: err.message });
  }
});

// --- Token Revocation ---
app.post('/auth/revoke', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'invalid_request', message: 'Token required' });
  }

  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.jti) {
      revokedTokens.add(decoded.jti);
    }
    res.json({ message: 'Token revoked successfully' });
  } catch (err) {
    // Even if decode fails, respond with 200 per RFC 7009
    res.json({ message: 'Token revocation processed' });
  }
});

// --- Token Validation Endpoint (for service providers) ---
app.post('/auth/validate', (req, res) => {
  const { token, expected_audience } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'invalid_request', message: 'Token required' });
  }

  try {
    let decoded;
    if (SECURE_MODE) {
      decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

      // Check revocation
      if (revokedTokens.has(decoded.jti)) {
        return res.status(401).json({ valid: false, error: 'token_revoked' });
      }

      // Check jti replay
      if (usedJtiTokens.has(decoded.jti)) {
        return res.status(401).json({ valid: false, error: 'token_replayed', message: 'JTI already used (replay attack detected)' });
      }
      usedJtiTokens.add(decoded.jti);

      // Validate audience
      if (expected_audience && decoded.aud !== expected_audience) {
        return res.status(401).json({ valid: false, error: 'invalid_audience' });
      }

      // Validate issuer
      if (decoded.iss !== 'http://localhost:4000') {
        return res.status(401).json({ valid: false, error: 'invalid_issuer' });
      }
    } else {
      // INSECURE: Just decode, no verification
      decoded = jwt.decode(token);
      if (!decoded) {
        return res.status(401).json({ valid: false, error: 'decode_failed' });
      }
      // INSECURE: No jti check, no issuer check, no audience check
    }

    res.json({
      valid: true,
      user: {
        sub: decoded.sub,
        email: decoded.email,
        role: decoded.role,
        name: decoded.name
      }
    });
  } catch (err) {
    return res.status(401).json({ valid: false, error: err.message });
  }
});

// --- Public Key Endpoint ---
app.get('/auth/public-key', (req, res) => {
  res.type('text/plain').send(PUBLIC_KEY);
});

// --- Start Server ---
initUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`[IdP] Identity Provider running on port ${PORT}`);
    console.log(`[IdP] SECURE_MODE: ${SECURE_MODE}`);
    console.log(`[IdP] Registered clients: ${clients.map(c => c.client_id).join(', ')}`);
  });
});

module.exports = app;
