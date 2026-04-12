const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Load public key for RS256 verification
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');
// Note: In Docker, __dirname is /app/rbac-middleware, so ../keys resolves to /app/keys

// In-memory JTI store for replay attack detection
const usedJtis = new Set();

/**
 * JWT Authentication Middleware
 * SECURE_MODE determines validation strictness
 */
function authenticate(options = {}) {
  const secureMode = process.env.SECURE_MODE === 'true';
  const expectedAudience = options.audience || null;

  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'missing_token', message: 'Authorization header with Bearer token required' });
    }

    const token = authHeader.split(' ')[1];

    try {
      let decoded;

      if (secureMode) {
        // SECURE: Full RS256 verification
        decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });

        // Validate issuer
        if (decoded.iss !== 'http://localhost:4000') {
          return res.status(401).json({ error: 'invalid_issuer', message: `Expected issuer http://localhost:4000, got ${decoded.iss}` });
        }

        // Validate audience
        if (expectedAudience && decoded.aud !== expectedAudience) {
          return res.status(401).json({ error: 'invalid_audience', message: `Expected audience ${expectedAudience}, got ${decoded.aud}` });
        }

        // Check JTI for replay attack
        if (decoded.jti) {
          if (usedJtis.has(decoded.jti)) {
            return res.status(401).json({ error: 'replay_detected', message: 'Token JTI already used (replay attack)' });
          }
          usedJtis.add(decoded.jti);

          // Clean old JTIs periodically (prevent memory leak)
          if (usedJtis.size > 10000) {
            usedJtis.clear();
          }
        }
      } else {
        // INSECURE: Just decode without verification
        // This is vulnerable to:
        // - alg:none attacks
        // - Token manipulation
        // - Replay attacks
        // - Issuer spoofing
        decoded = jwt.decode(token);
        if (!decoded) {
          return res.status(401).json({ error: 'invalid_token', message: 'Unable to decode token' });
        }

        // INSECURE: No issuer validation
        // INSECURE: No audience validation
        // INSECURE: No JTI replay check
        // INSECURE: No signature verification
      }

      // Check expiry (both modes check this)
      if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
        return res.status(401).json({ error: 'token_expired', message: 'Token has expired' });
      }

      // Attach user info to request
      req.user = {
        sub: decoded.sub,
        email: decoded.email,
        role: decoded.role,
        name: decoded.name,
        iss: decoded.iss,
        aud: decoded.aud,
        jti: decoded.jti
      };

      next();
    } catch (err) {
      return res.status(401).json({ error: 'token_verification_failed', message: err.message });
    }
  };
}

/**
 * Role-Based Access Control Middleware
 */
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'not_authenticated' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'forbidden',
        message: `Role '${req.user.role}' not authorized. Required: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
}

module.exports = { authenticate, authorize };
