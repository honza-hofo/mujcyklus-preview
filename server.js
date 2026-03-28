require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;

// PostgreSQL (shared DB with mc_ prefix)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Init DB
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mc_users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(100),
        age INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS mc_user_data (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES mc_users(id),
        settings JSONB DEFAULT '{}',
        day_data JSONB DEFAULT '{}',
        notifications JSONB DEFAULT '[]',
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id)
      );
      CREATE TABLE IF NOT EXISTS mc_login_attempts (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(45),
        email VARCHAR(255),
        attempted_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('DB tables ready');
  } catch (e) {
    console.error('DB init error:', e.message);
  }
}
initDB();

// Trust proxy (Render)
app.set('trust proxy', 1);

// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// CSRF token
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

function checkCsrf(req, res, next) {
  if (req.method === 'GET') return next();
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  if (token && token === req.session.csrfToken) return next();
  // Skip CSRF for API login/register (no session yet)
  if (req.path === '/api/login' || req.path === '/api/register') return next();
  res.status(403).json({ error: 'Invalid CSRF token' });
}
app.use(checkCsrf);

// Rate limiting (in-memory, simple)
const loginAttempts = {};
function checkRateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  if (!loginAttempts[ip]) loginAttempts[ip] = [];
  loginAttempts[ip] = loginAttempts[ip].filter(t => now - t < 15 * 60 * 1000); // 15 min window
  if (loginAttempts[ip].length >= 10) {
    return res.status(429).json({ error: 'Prilis mnoho pokusu. Zkuste to za 15 minut.' });
  }
  loginAttempts[ip].push(now);
  next();
}

// Force HTTPS
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.hostname + req.url);
  }
  next();
});

// Static files
app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Prihlaste se' });
}

// Register
app.post('/api/register', checkRateLimit, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email a heslo jsou povinne' });
    if (password.length < 6) return res.status(400).json({ error: 'Heslo musi mit alespon 6 znaku' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Neplatny email' });

    const existing = await pool.query('SELECT id FROM mc_users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Tento email je jiz registrovan' });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO mc_users (email, password, name) VALUES ($1, $2, $3) RETURNING id',
      [email.toLowerCase(), hash, name || null]
    );

    await pool.query('INSERT INTO mc_user_data (user_id) VALUES ($1)', [result.rows[0].id]);

    req.session.userId = result.rows[0].id;
    req.session.email = email.toLowerCase();
    res.json({ ok: true, email: email.toLowerCase(), csrfToken: req.session.csrfToken });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Login
app.post('/api/login', checkRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Vyplnte email a heslo' });

    const result = await pool.query('SELECT id, email, password, name FROM mc_users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Spatny email nebo heslo' });

    const valid = await bcrypt.compare(password, result.rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Spatny email nebo heslo' });

    req.session.userId = result.rows[0].id;
    req.session.email = result.rows[0].email;
    res.json({ ok: true, email: result.rows[0].email, name: result.rows[0].name, csrfToken: req.session.csrfToken });
  } catch (e) {
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// Auth check
app.get('/api/me', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, email: req.session.email, csrfToken: req.session.csrfToken });
  } else {
    res.json({ loggedIn: false });
  }
});

// Save data
app.post('/api/data', requireAuth, async (req, res) => {
  try {
    const { settings, dayData, notifications } = req.body;
    await pool.query(
      `INSERT INTO mc_user_data (user_id, settings, day_data, notifications, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id) DO UPDATE SET
       settings = $2, day_data = $3, notifications = $4, updated_at = NOW()`,
      [req.session.userId, JSON.stringify(settings || {}), JSON.stringify(dayData || {}), JSON.stringify(notifications || [])]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba pri ukladani' });
  }
});

// Load data
app.get('/api/data', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT settings, day_data, notifications FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    if (result.rows.length > 0) {
      res.json({
        settings: result.rows[0].settings || {},
        dayData: result.rows[0].day_data || {},
        notifications: result.rows[0].notifications || []
      });
    } else {
      res.json({ settings: {}, dayData: {}, notifications: [] });
    }
  } catch (e) {
    res.status(500).json({ error: 'Chyba pri nacitani' });
  }
});

// Password reset request (simple - just changes password if email matches)
app.post('/api/reset-password', checkRateLimit, async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ error: 'Vyplnte email a nove heslo' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Heslo musi mit alespon 6 znaku' });

    const user = await pool.query('SELECT id FROM mc_users WHERE email = $1', [email.toLowerCase()]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'Ucet nenalezen' });

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE mc_users SET password = $1 WHERE email = $2', [hash, email.toLowerCase()]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Delete account (GDPR)
app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    await pool.query('DELETE FROM mc_users WHERE id = $1', [req.session.userId]);
    req.session.destroy();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Chyba pri mazani uctu' });
  }
});

// Export data (for doctor)
app.get('/api/export', requireAuth, async (req, res) => {
  try {
    const user = await pool.query('SELECT email, name, age FROM mc_users WHERE id = $1', [req.session.userId]);
    const data = await pool.query('SELECT settings, day_data FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    res.json({
      user: user.rows[0] || {},
      data: data.rows[0] || {},
      exportedAt: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: 'Chyba pri exportu' });
  }
});

// Landing = default, app = /app
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/landing', (req, res) => res.sendFile(path.join(__dirname, 'landing.html')));

app.listen(PORT, () => console.log(`MujCyklus server on port ${PORT}`));
