const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = 4001;

const PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8');
const PUBLIC_KEY = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');

const SECURE_MODE = process.env.SECURE_MODE === 'true';

app.use(express.json());
app.use(cors());
app.use(morgan('combined'));

// --- Health ---
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'jwt-service', secureMode: SECURE_MODE });
});

// --- Sign Token ---
app.post('/sign', (req, res) => {
  const { payload } = req.body;
  if (!payload) return res.status(400).json({ error: 'Payload required' });

  const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  res.json({ token });
});

// --- Verify Token ---
app.post('/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });

  try {
    let decoded;
    if (SECURE_MODE) {
      decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] });
    } else {
      // INSECURE: decode without verification
      decoded = jwt.decode(token);
    }
    res.json({ valid: true, decoded });
  } catch (err) {
    res.json({ valid: false, error: err.message });
  }
});

// --- Public Key ---
app.get('/public-key', (req, res) => {
  res.type('text/plain').send(PUBLIC_KEY);
});

app.listen(PORT, () => {
  console.log(`[JWT Service] Running on port ${PORT}, SECURE_MODE: ${SECURE_MODE}`);
});

module.exports = app;
