require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// SQLite
const db = new Database(path.join(__dirname, 'mujcyklus.db'));
db.pragma('journal_mode = WAL');

// Init tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    age INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS user_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE REFERENCES users(id),
    settings TEXT DEFAULT '{}',
    day_data TEXT DEFAULT '{}',
    notifications TEXT DEFAULT '[]',
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mujcyklus-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname)));

function requireAuth(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Prihlaste se' });
}

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email a heslo jsou povinne' });
    if (password.length < 6) return res.status(400).json({ error: 'Heslo musi mit alespon 6 znaku' });

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) return res.status(400).json({ error: 'Tento email je jiz registrovan' });

    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)').run(email.toLowerCase(), hash, name || null);

    db.prepare('INSERT INTO user_data (user_id) VALUES (?)').run(result.lastInsertRowid);

    req.session.userId = result.lastInsertRowid;
    req.session.email = email.toLowerCase();
    res.json({ ok: true, email: email.toLowerCase() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT id, email, password, name FROM users WHERE email = ?').get(email.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Spatny email nebo heslo' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Spatny email nebo heslo' });

    req.session.userId = user.id;
    req.session.email = user.email;
    res.json({ ok: true, email: user.email, name: user.name });
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
    res.json({ loggedIn: true, email: req.session.email });
  } else {
    res.json({ loggedIn: false });
  }
});

// Save data
app.post('/api/data', requireAuth, (req, res) => {
  try {
    const { settings, dayData, notifications } = req.body;
    const existing = db.prepare('SELECT id FROM user_data WHERE user_id = ?').get(req.session.userId);
    if (existing) {
      db.prepare(`UPDATE user_data SET settings = ?, day_data = ?, notifications = ?, updated_at = datetime('now') WHERE user_id = ?`)
        .run(JSON.stringify(settings || {}), JSON.stringify(dayData || {}), JSON.stringify(notifications || []), req.session.userId);
    } else {
      db.prepare('INSERT INTO user_data (user_id, settings, day_data, notifications) VALUES (?, ?, ?, ?)')
        .run(req.session.userId, JSON.stringify(settings || {}), JSON.stringify(dayData || {}), JSON.stringify(notifications || []));
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba pri ukladani' });
  }
});

// Load data
app.get('/api/data', requireAuth, (req, res) => {
  try {
    const row = db.prepare('SELECT settings, day_data, notifications FROM user_data WHERE user_id = ?').get(req.session.userId);
    if (row) {
      res.json({
        settings: JSON.parse(row.settings || '{}'),
        dayData: JSON.parse(row.day_data || '{}'),
        notifications: JSON.parse(row.notifications || '[]')
      });
    } else {
      res.json({ settings: {}, dayData: {}, notifications: [] });
    }
  } catch (e) {
    res.status(500).json({ error: 'Chyba pri nacitani' });
  }
});

app.listen(PORT, () => console.log(`MujCyklus server on port ${PORT}`));
