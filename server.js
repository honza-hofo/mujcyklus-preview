require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Email
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', port: 587, secure: false,
  auth: { user: process.env.SMTP_USER || 'honza@hofo.cz', pass: process.env.SMTP_PASS }
});

async function sendVerifyEmail(to, code) {
  await transporter.sendMail({
    from: '"MůjCyklus" <honza@hofo.cz>',
    to,
    subject: 'Ověření účtu - MůjCyklus',
    html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;text-align:center">
      <h2 style="color:#E8577D">MůjCyklus</h2>
      <p>Tvůj ověřovací kód:</p>
      <div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:20px;background:#f5f5f5;border-radius:8px;margin:20px 0">${code}</div>
      <p style="color:#888;font-size:13px">Kód platí 15 minut. Pokud jsi se neregistrovala, ignoruj tento email.</p>
    </div>`
  });
}

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
      CREATE TABLE IF NOT EXISTS mc_partner_shares (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES mc_users(id) ON DELETE CASCADE,
        share_code VARCHAR(6) UNIQUE NOT NULL,
        partner_email VARCHAR(255),
        show_period BOOLEAN DEFAULT true,
        show_fertile BOOLEAN DEFAULT true,
        show_moods BOOLEAN DEFAULT false,
        show_symptoms BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS mc_gdpr_consents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES mc_users(id) ON DELETE CASCADE,
        consent_type VARCHAR(100) NOT NULL,
        consented BOOLEAN DEFAULT false,
        ip_address VARCHAR(45),
        consented_at TIMESTAMP DEFAULT NOW()
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

// Register - step 1: send verification code
app.post('/api/register', checkRateLimit, async (req, res) => {
  try {
    const { email, password, name, age, consent_terms, consent_health_data, consent_age } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email a heslo jsou povinné' });
    if (password.length < 6) return res.status(400).json({ error: 'Heslo musí mít alespoň 6 znaků' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Neplatný email' });
    if (age && parseInt(age) < 15) return res.status(400).json({ error: 'Pro registraci musíte mít alespoň 15 let (§7 zákona 110/2019 Sb.)' });
    if (!consent_terms) return res.status(400).json({ error: 'Musíte souhlasit s obchodními podmínkami' });
    if (!consent_health_data) return res.status(400).json({ error: 'Pro sledování menstruačního cyklu je nutný výslovný souhlas se zpracováním údajů o zdravotním stavu (čl. 9 GDPR)' });
    if (!consent_age) return res.status(400).json({ error: 'Musíte potvrdit, že vám je alespoň 15 let' });

    const existing = await pool.query('SELECT id FROM mc_users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Tento email je již registrován' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    req.session.pendingReg = { email: email.toLowerCase(), password, name, age: age ? parseInt(age) : null, code, expires: Date.now() + 15 * 60 * 1000, consent_terms: true, consent_health_data: true, ip: req.ip };

    try {
      await sendVerifyEmail(email, code);
    } catch (emailErr) {
      console.error('Email error:', emailErr);
      return res.status(500).json({ error: 'Nepodařilo se odeslat ověřovací email' });
    }

    res.json({ ok: true, needsVerify: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Register - step 2: verify code
app.post('/api/verify', async (req, res) => {
  try {
    const { code } = req.body;
    const pending = req.session.pendingReg;
    if (!pending) return res.status(400).json({ error: 'Nejdřív se zaregistrujte' });
    if (Date.now() > pending.expires) { delete req.session.pendingReg; return res.status(400).json({ error: 'Kód vypršel. Zaregistrujte se znovu.' }); }
    if (code !== pending.code) return res.status(400).json({ error: 'Špatný kód' });

    const hash = await bcrypt.hash(pending.password, 12);
    const result = await pool.query(
      'INSERT INTO mc_users (email, password, name, age) VALUES ($1, $2, $3, $4) RETURNING id',
      [pending.email, hash, pending.name || null, pending.age || null]
    );
    await pool.query('INSERT INTO mc_user_data (user_id) VALUES ($1)', [result.rows[0].id]);

    // Store GDPR consents
    const userId = result.rows[0].id;
    const ip = pending.ip || req.ip;
    await pool.query(
      'INSERT INTO mc_gdpr_consents (user_id, consent_type, consented, ip_address) VALUES ($1, $2, $3, $4)',
      [userId, 'terms_of_service', true, ip]
    );
    await pool.query(
      'INSERT INTO mc_gdpr_consents (user_id, consent_type, consented, ip_address) VALUES ($1, $2, $3, $4)',
      [userId, 'health_data_processing', true, ip]
    );
    await pool.query(
      'INSERT INTO mc_gdpr_consents (user_id, consent_type, consented, ip_address) VALUES ($1, $2, $3, $4)',
      [userId, 'age_confirmation_15plus', true, ip]
    );

    req.session.userId = userId;
    req.session.email = pending.email;
    delete req.session.pendingReg;
    res.json({ ok: true, email: pending.email, csrfToken: req.session.csrfToken });
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

// Generate partner share code
app.post('/api/partner/share', requireAuth, async (req, res) => {
  try {
    const { partnerEmail, showPeriod, showFertile, showMoods, showSymptoms } = req.body;

    // Check if user already has a share
    const existing = await pool.query('SELECT id, share_code FROM mc_partner_shares WHERE user_id = $1', [req.session.userId]);

    let code;
    if (existing.rows.length > 0) {
      // Update existing
      code = existing.rows[0].share_code;
      await pool.query(
        'UPDATE mc_partner_shares SET partner_email = $1, show_period = $2, show_fertile = $3, show_moods = $4, show_symptoms = $5 WHERE user_id = $6',
        [partnerEmail || null, showPeriod !== false, showFertile !== false, showMoods || false, showSymptoms || false, req.session.userId]
      );
    } else {
      // Create new
      code = Math.random().toString(36).substring(2, 8).toUpperCase();
      await pool.query(
        'INSERT INTO mc_partner_shares (user_id, share_code, partner_email, show_period, show_fertile, show_moods, show_symptoms) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [req.session.userId, code, partnerEmail || null, showPeriod !== false, showFertile !== false, showMoods || false, showSymptoms || false]
      );
    }

    // Send email to partner if email provided
    if (partnerEmail) {
      try {
        const user = await pool.query('SELECT name, email FROM mc_users WHERE id = $1', [req.session.userId]);
        const userName = user.rows[0].name || user.rows[0].email;
        await transporter.sendMail({
          from: '"MůjCyklus" <honza@hofo.cz>',
          to: partnerEmail,
          subject: userName + ' s tebou sdílí svůj cyklus',
          html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;text-align:center">' +
            '<h2 style="color:#E8577D">MůjCyklus</h2>' +
            '<p><strong>' + userName + '</strong> s tebou sdílí přehled svého cyklu.</p>' +
            '<p>Otevři tento odkaz:</p>' +
            '<a href="https://mujcyklus-preview.onrender.com/partner.html?code=' + code + '" style="display:inline-block;padding:14px 32px;background:#E8577D;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;margin:16px 0">Zobrazit cyklus</a>' +
            '<p style="color:#888;font-size:13px;margin-top:16px">Nebo zadej kód: <strong>' + code + '</strong></p>' +
            '</div>'
        });
      } catch (emailErr) {
        console.error('Partner email error:', emailErr);
      }
    }

    res.json({ ok: true, code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Get partner share settings
app.get('/api/partner/share', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT share_code, partner_email, show_period, show_fertile, show_moods, show_symptoms FROM mc_partner_shares WHERE user_id = $1', [req.session.userId]);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.json({ share_code: null });
    }
  } catch (e) {
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Partner view - get shared data (no auth needed, uses code)
app.get('/api/partner/view/:code', async (req, res) => {
  try {
    const share = await pool.query(
      'SELECT s.*, u.name, u.email FROM mc_partner_shares s JOIN mc_users u ON s.user_id = u.id WHERE s.share_code = $1',
      [req.params.code.toUpperCase()]
    );
    if (share.rows.length === 0) return res.status(404).json({ error: 'Neplatný kód' });

    const s = share.rows[0];
    const data = await pool.query('SELECT settings, day_data FROM mc_user_data WHERE user_id = $1', [s.user_id]);

    if (data.rows.length === 0) return res.json({ name: s.name, data: {} });

    const settings = JSON.parse(typeof data.rows[0].settings === 'string' ? data.rows[0].settings : JSON.stringify(data.rows[0].settings));
    const dayData = JSON.parse(typeof data.rows[0].day_data === 'string' ? data.rows[0].day_data : JSON.stringify(data.rows[0].day_data));

    // Filter based on permissions
    const filtered = {};
    for (const [date, dd] of Object.entries(dayData)) {
      const entry = {};
      if (s.show_period && dd.period) entry.period = true;
      if (s.show_moods && dd.mood) entry.mood = dd.mood;
      if (s.show_symptoms && dd.symptoms) entry.symptoms = dd.symptoms;
      if (Object.keys(entry).length > 0) filtered[date] = entry;
    }

    res.json({
      name: s.name || s.email.split('@')[0],
      showPeriod: s.show_period,
      showFertile: s.show_fertile,
      showMoods: s.show_moods,
      showSymptoms: s.show_symptoms,
      settings: { cycleLength: settings.cycleLength || 28, periodLength: settings.periodLength || 5, lutealPhase: settings.lutealPhase || 14 },
      dayData: filtered
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Delete partner share
app.delete('/api/partner/share', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM mc_partner_shares WHERE user_id = $1', [req.session.userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// AI Analysis
app.post('/api/ai/analyze', requireAuth, async (req, res) => {
  try {
    const userData = await pool.query('SELECT settings, day_data FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    const user = await pool.query('SELECT name, age FROM mc_users WHERE id = $1', [req.session.userId]);
    if (!userData.rows.length) return res.json({ analysis: 'Nedostatek dat pro analýzu.' });

    const settings = userData.rows[0].settings || {};
    const dayData = userData.rows[0].day_data || {};
    const age = user.rows[0]?.age || null;
    const { question } = req.body;

    // Prepare cycle summary
    const periodDays = Object.entries(dayData).filter(([k,v]) => v.period).map(([k]) => k).sort();
    const moodEntries = Object.entries(dayData).filter(([k,v]) => v.mood).map(([k,v]) => `${k}: ${v.mood}`);
    const symptomEntries = Object.entries(dayData).filter(([k,v]) => v.symptoms && v.symptoms.length > 0).map(([k,v]) => `${k}: ${v.symptoms.join(', ')}`);

    const systemPrompt = `Jsi laskavá a profesionální AI asistentka v aplikaci MůjCyklus (menstruační kalendář). Odpovídáš česky, stručně a srozumitelně. Nejsi lékařka - vždy upozorni že tvoje rady nenahrazují návštěvu gynekologa. Používej přátelský tón.

Data uživatelky:
- Věk: ${age || 'neuvedeno'}
- Délka cyklu: ${settings.cycleLength || 28} dní
- Délka menstruace: ${settings.periodLength || 5} dní
- Zaznamenané dny menstruace: ${periodDays.slice(-30).join(', ') || 'žádné'}
- Nálady (posledních 30 záznamů): ${moodEntries.slice(-15).join('; ') || 'žádné'}
- Symptomy (posledních 30 záznamů): ${symptomEntries.slice(-15).join('; ') || 'žádné'}`;

    let userPrompt;
    if (question) {
      userPrompt = question;
    } else {
      userPrompt = 'Proveď kompletní analýzu mého cyklu. Zaměř se na: 1) Pravidelnost cyklu 2) Vzorce v náladách a symptomech 3) Případná upozornění na anomálie 4) Doporučení. Buď stručná, max 300 slov.';
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return res.json({ analysis: 'AI analýza není dostupná (chybí API klíč).' });

    const https = require('https');
    const postData = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 800,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    });

    const aiResp = await new Promise((resolve, reject) => {
      const aiReq = https.request({
        hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(postData) }
      }, (aiRes) => {
        let data = '';
        aiRes.on('data', d => data += d);
        aiRes.on('end', () => resolve(JSON.parse(data)));
      });
      aiReq.on('error', reject);
      aiReq.write(postData);
      aiReq.end();
    });

    const text = aiResp.content?.[0]?.text || 'Nepodařilo se získat analýzu.';
    res.json({ analysis: text });
  } catch (e) {
    console.error('AI error:', e);
    res.status(500).json({ error: 'Chyba AI analýzy' });
  }
});

// Email notifications - check and send reminders
app.post('/api/notifications/check', requireAuth, async (req, res) => {
  try {
    const userData = await pool.query('SELECT settings, day_data FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    const user = await pool.query('SELECT email, name FROM mc_users WHERE id = $1', [req.session.userId]);
    if (!userData.rows.length || !user.rows.length) return res.json({ sent: false });

    const settings = userData.rows[0].settings || {};
    const dayData = userData.rows[0].day_data || {};
    const email = user.rows[0].email;
    const name = user.rows[0].name || '';

    // Find last period start
    const periodDays = Object.keys(dayData).filter(k => dayData[k].period).sort();
    if (periodDays.length === 0) return res.json({ sent: false });

    // Calculate next period
    const cycleLen = settings.cycleLength || 28;
    const lastStart = new Date(periodDays[periodDays.length - 1]);
    // Find actual cycle start (first day of last period)
    let cycleStart = new Date(lastStart);
    while (periodDays.includes(fmtDateServer(new Date(cycleStart.getTime() - 86400000)))) {
      cycleStart.setDate(cycleStart.getDate() - 1);
    }

    const nextPeriod = new Date(cycleStart);
    nextPeriod.setDate(nextPeriod.getDate() + cycleLen);

    const today = new Date();
    const daysUntil = Math.round((nextPeriod - today) / 86400000);

    let sent = false;
    if (daysUntil >= 1 && daysUntil <= 3) {
      // Send reminder
      try {
        await transporter.sendMail({
          from: '"MůjCyklus" <' + (process.env.SMTP_USER || 'honza@hofo.cz') + '>',
          to: email,
          subject: 'Menstruace za ' + daysUntil + (daysUntil === 1 ? ' den' : ' dny'),
          html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;text-align:center">' +
            '<h2 style="color:#E8577D">MůjCyklus</h2>' +
            '<p>Ahoj' + (name ? ' ' + name : '') + ',</p>' +
            '<p>Podle tvých dat by měla menstruace začít za <strong>' + daysUntil + (daysUntil === 1 ? ' den' : ' dny') + '</strong>.</p>' +
            '<p style="color:#888;font-size:13px;margin-top:20px">Toto je automatické upozornění z aplikace MůjCyklus.</p>' +
            '</div>'
        });
        sent = true;
      } catch (emailErr) {
        console.error('Notification email error:', emailErr);
      }
    }

    res.json({ sent, daysUntil, nextPeriod: nextPeriod.toISOString().split('T')[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Chyba' });
  }
});

function fmtDateServer(d) {
  return d.toISOString().split('T')[0];
}

// PDF-like export (HTML for printing)
app.get('/api/export/pdf', requireAuth, async (req, res) => {
  try {
    const userData = await pool.query('SELECT settings, day_data FROM mc_user_data WHERE user_id = $1', [req.session.userId]);
    const user = await pool.query('SELECT email, name, age FROM mc_users WHERE id = $1', [req.session.userId]);
    if (!userData.rows.length) return res.send('Žádná data');

    const settings = userData.rows[0].settings || {};
    const dayData = userData.rows[0].day_data || {};
    const u = user.rows[0] || {};

    const periodDays = Object.keys(dayData).filter(k => dayData[k].period).sort();
    const symptomDays = Object.entries(dayData).filter(([k,v]) => v.symptoms && v.symptoms.length > 0).map(([k,v]) => k + ': ' + v.symptoms.join(', ')).slice(-20);
    const moodDays = Object.entries(dayData).filter(([k,v]) => v.mood).map(([k,v]) => k + ': ' + v.mood).slice(-20);

    res.send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>MůjCyklus - Export</title>' +
      '<style>body{font-family:Arial,sans-serif;max-width:700px;margin:40px auto;padding:20px;color:#333}' +
      'h1{color:#E8577D;font-size:24px}h2{font-size:16px;margin-top:24px;border-bottom:1px solid #eee;padding-bottom:8px}' +
      'table{width:100%;border-collapse:collapse;margin:12px 0}td,th{padding:8px 12px;border:1px solid #ddd;text-align:left;font-size:13px}' +
      'th{background:#f5f5f5}p{font-size:14px;line-height:1.6}.print-btn{background:#E8577D;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-size:14px}' +
      '@media print{.print-btn{display:none}}</style></head><body>' +
      '<button class="print-btn" onclick="window.print()">Vytisknout / Uložit PDF</button>' +
      '<h1>MůjCyklus - Zdravotní report</h1>' +
      '<p>Datum exportu: ' + new Date().toLocaleDateString('cs-CZ') + '</p>' +
      '<table><tr><th>Jméno</th><td>' + (u.name || '-') + '</td></tr>' +
      '<tr><th>Věk</th><td>' + (u.age || '-') + '</td></tr>' +
      '<tr><th>Email</th><td>' + (u.email || '-') + '</td></tr>' +
      '<tr><th>Délka cyklu</th><td>' + (settings.cycleLength || 28) + ' dní</td></tr>' +
      '<tr><th>Délka menstruace</th><td>' + (settings.periodLength || 5) + ' dní</td></tr></table>' +
      '<h2>Záznamy menstruace (posledních 30)</h2><p>' + (periodDays.slice(-30).join(', ') || 'Žádné záznamy') + '</p>' +
      '<h2>Symptomy (posledních 20)</h2>' + (symptomDays.length > 0 ? '<ul>' + symptomDays.map(s => '<li>' + s + '</li>').join('') + '</ul>' : '<p>Žádné záznamy</p>') +
      '<h2>Nálady (posledních 20)</h2>' + (moodDays.length > 0 ? '<ul>' + moodDays.map(s => '<li>' + s + '</li>').join('') + '</ul>' : '<p>Žádné záznamy</p>') +
      '<p style="margin-top:32px;color:#888;font-size:12px">Vygenerováno aplikací MůjCyklus. Tento report nenahrazuje lékařské vyšetření.</p>' +
      '</body></html>');
  } catch (e) {
    res.status(500).send('Chyba při generování reportu');
  }
});

// ========== GDPR ENDPOINTS ==========

// Serve privacy policy and terms pages
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/podminky', (req, res) => res.sendFile(path.join(__dirname, 'podminky.html')));

// GDPR: Delete account and all data
app.post('/api/gdpr/delete-account', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const email = req.session.email;
    const ip = req.ip;

    // Delete all related data in correct order (foreign keys)
    await pool.query('DELETE FROM mc_partner_shares WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM mc_user_data WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM mc_gdpr_consents WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM mc_login_attempts WHERE email = $1 OR ip = $2', [email, ip]);
    await pool.query('DELETE FROM mc_users WHERE id = $1', [userId]);

    req.session.destroy();
    console.log(`GDPR: Account deleted for user ${userId} (${email})`);
    res.json({ ok: true, message: 'Účet a všechna data byla trvale smazána.' });
  } catch (e) {
    console.error('GDPR delete error:', e);
    res.status(500).json({ error: 'Chyba při mazání účtu' });
  }
});

// GDPR: Export all user data (data portability - Art. 20)
app.get('/api/gdpr/export-data', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;

    const user = await pool.query('SELECT id, email, name, age, created_at FROM mc_users WHERE id = $1', [userId]);
    const userData = await pool.query('SELECT settings, day_data, notifications, updated_at FROM mc_user_data WHERE user_id = $1', [userId]);
    const partnerShares = await pool.query('SELECT share_code, partner_email, show_period, show_fertile, show_moods, show_symptoms, created_at FROM mc_partner_shares WHERE user_id = $1', [userId]);
    const consents = await pool.query('SELECT consent_type, consented, ip_address, consented_at FROM mc_gdpr_consents WHERE user_id = $1 ORDER BY consented_at', [userId]);

    const exportData = {
      data_controller: {
        company: 'HOFO Media Group s.r.o.',
        ico: '07900171',
        email: 'honza@hofo.cz',
        address: 'Česká republika'
      },
      export_info: {
        exported_at: new Date().toISOString(),
        gdpr_article: 'Čl. 20 GDPR - Právo na přenositelnost údajů',
        format: 'JSON'
      },
      user_profile: user.rows[0] || {},
      cycle_data: userData.rows[0] || {},
      partner_shares: partnerShares.rows,
      gdpr_consents: consents.rows
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="mujcyklus_gdpr_export_' + new Date().toISOString().split('T')[0] + '.json"');
    res.json(exportData);
  } catch (e) {
    console.error('GDPR export error:', e);
    res.status(500).json({ error: 'Chyba při exportu dat' });
  }
});

// GDPR: Get consent history
app.get('/api/gdpr/consents', requireAuth, async (req, res) => {
  try {
    const consents = await pool.query(
      'SELECT consent_type, consented, ip_address, consented_at FROM mc_gdpr_consents WHERE user_id = $1 ORDER BY consented_at DESC',
      [req.session.userId]
    );
    res.json({ consents: consents.rows });
  } catch (e) {
    console.error('GDPR consents error:', e);
    res.status(500).json({ error: 'Chyba při načítání souhlasů' });
  }
});

// ========== CLEANUP ENDPOINT ==========
app.post('/api/cleanup', async (req, res) => {
  const cronSecret = req.headers['x-cron-secret'] || req.headers['authorization'];
  if (!cronSecret || cronSecret !== process.env.CRON_SECRET) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const result = await pool.query("DELETE FROM mc_login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'");
    console.log(`Cleanup: Deleted ${result.rowCount} old login attempts`);
    res.json({ ok: true, deleted_login_attempts: result.rowCount });
  } catch (e) {
    console.error('Cleanup error:', e);
    res.status(500).json({ error: 'Cleanup failed' });
  }
});

app.listen(PORT, () => console.log(`MujCyklus server on port ${PORT}`));
