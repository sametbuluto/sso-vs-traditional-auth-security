const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const app = express();

const SERVICE_NAME = process.env.SERVICE_NAME || 'service-a';
const PORT = parseInt(process.env.PORT) || 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'insecure-secret-a';

// --- Middleware ---
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(morgan('combined'));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 hour
  // NOTE: No 'secure' flag, no 'httpOnly' flag — intentionally insecure
}));

// --- User Database (file-based, per-service) ---
const DB_PATH = path.join(__dirname, 'db.json');

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return { users: [] };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// --- ENDPOINTS ---

// Health Check (for SPOF test T3/T8)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: SERVICE_NAME,
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Register
app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const db = readDB();
  if (db.users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.users.push({
    email,
    password: hashedPassword,
    role: role || 'user',
    createdAt: new Date().toISOString()
  });
  writeDB(db);

  res.status(201).json({ message: 'User registered', service: SERVICE_NAME, email });
});

// Login
// NOTE: No rate limiting — intentionally vulnerable to brute-force (T1)
// NOTE: No MFA — intentionally reduced security
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const startTime = Date.now();

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const db = readDB();
  const user = db.users.find(u => u.email === email);

  if (!user) {
    return res.status(401).json({
      error: 'Invalid credentials',
      service: SERVICE_NAME,
      responseTime: Date.now() - startTime
    });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({
      error: 'Invalid credentials',
      service: SERVICE_NAME,
      responseTime: Date.now() - startTime
    });
  }

  // Set session
  req.session.user = {
    email: user.email,
    role: user.role
  };

  res.json({
    message: 'Login successful',
    service: SERVICE_NAME,
    user: { email: user.email, role: user.role },
    responseTime: Date.now() - startTime
  });
});

// Dashboard (session-protected)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated', service: SERVICE_NAME });
  }

  res.json({
    service: SERVICE_NAME,
    message: `Welcome to ${SERVICE_NAME} dashboard`,
    user: req.session.user,
    data: {
      items: [
        { id: 1, name: `${SERVICE_NAME} Item 1`, type: 'document' },
        { id: 2, name: `${SERVICE_NAME} Item 2`, type: 'report' }
      ]
    }
  });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logged out', service: SERVICE_NAME });
  });
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`[${SERVICE_NAME}] Traditional auth service running on port ${PORT}`);

  // Initialize db with test users if empty
  const db = readDB();
  if (db.users.length === 0) {
    console.log(`[${SERVICE_NAME}] Initializing test users...`);
    const passwords = {
      'user@test.com': 'password123',
      'admin@test.com': 'adminpass',
      'victim@test.com': 'victim123'
    };

    Promise.all(Object.entries(passwords).map(async ([email, pass]) => {
      const hash = await bcrypt.hash(pass, 10);
      const role = email.includes('admin') ? 'admin' : 'user';
      db.users.push({ email, password: hash, role, createdAt: new Date().toISOString() });
    })).then(() => {
      writeDB(db);
      console.log(`[${SERVICE_NAME}] ${db.users.length} test users created`);
    });
  }
});

module.exports = app;
