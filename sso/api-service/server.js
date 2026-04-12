const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { authenticate, authorize } = require('./rbac-middleware');

const app = express();

const SERVICE_NAME = process.env.SERVICE_NAME || 'service-a';
const PORT = parseInt(process.env.PORT) || 4002;
const CLIENT_ID = process.env.CLIENT_ID || 'service-a';

app.use(express.json());
app.use(cors());
app.use(morgan('combined'));

// --- Health Check ---
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: SERVICE_NAME,
    port: PORT,
    secureMode: process.env.SECURE_MODE === 'true',
    timestamp: new Date().toISOString()
  });
});

// --- OAuth Callback ---
app.get('/callback', (req, res) => {
  const { code, state } = req.query;
  res.json({
    message: 'Callback received',
    service: SERVICE_NAME,
    code: code || null,
    state: state || null,
    info: 'Exchange this code at IdP /auth/token endpoint'
  });
});

// --- Protected Dashboard ---
app.get('/dashboard', authenticate({ audience: CLIENT_ID }), (req, res) => {
  res.json({
    service: SERVICE_NAME,
    message: `Welcome to ${SERVICE_NAME} dashboard`,
    user: req.user,
    data: {
      items: [
        { id: 1, name: `${SERVICE_NAME} Item 1`, type: 'document' },
        { id: 2, name: `${SERVICE_NAME} Item 2`, type: 'report' }
      ]
    }
  });
});

// --- Admin-only Endpoint ---
app.get('/admin', authenticate({ audience: CLIENT_ID }), authorize('admin'), (req, res) => {
  res.json({
    service: SERVICE_NAME,
    message: 'Admin area',
    user: req.user,
    adminData: { totalUsers: 3, totalSessions: 12 }
  });
});

// --- Logout (Token Revocation) ---
app.post('/logout', (req, res) => {
  const { token } = req.body;
  // In a real system, forward to IdP revocation endpoint
  res.json({ message: 'Logged out', service: SERVICE_NAME });
});

app.listen(PORT, () => {
  console.log(`[${SERVICE_NAME}] Running on port ${PORT}, CLIENT_ID: ${CLIENT_ID}, SECURE_MODE: ${process.env.SECURE_MODE}`);
});

module.exports = app;
