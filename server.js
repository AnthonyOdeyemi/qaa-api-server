const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(cors());
app.use(express.json());

// ── DATABASE CONNECTION ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── INITIALISE DATABASE TABLES ──
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        nbte_number VARCHAR(100),
        skill_areas TEXT[],
        password_hash VARCHAR(255) NOT NULL,
        free_reports_used INTEGER DEFAULT 0,
        paid_credits INTEGER DEFAULT 0,
        total_reports_generated INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP
      );

      -- Migrations: add columns that older versions of the table may lack
      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS nbte_number VARCHAR(100);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS skill_areas TEXT[];
      ALTER TABLE users ADD COLUMN IF NOT EXISTS free_reports_used INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS paid_credits INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS total_reports_generated INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();
      ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        paystack_reference VARCHAR(255) UNIQUE,
        bundle_name VARCHAR(100),
        reports_credited INTEGER,
        amount_kobo INTEGER,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        verified_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS report_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        report_type VARCHAR(100),
        skill VARCHAR(255),
        unit_number VARCHAR(50),
        credit_type VARCHAR(20),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(128) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('Database tables initialised');
  } catch (err) {
    console.error('Database init error:', err.message);
  }
}
initDB();

// ── HELPERS ──
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + process.env.SALT || 'qaa2026').digest('hex');
}

function tokenSecret() {
  return process.env.TOKEN_SECRET || process.env.DATABASE_URL || 'qaa-fallback-secret';
}

// Signed token: base64url(userId:email:expiry).HMAC — cannot be forged without the server secret
function generateToken(userId, email) {
  const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;
  const payload = Buffer.from(`${userId}:${email}:${exp}`).toString('base64url');
  const sig = crypto.createHmac('sha256', tokenSecret()).update(payload).digest('hex');
  return payload + '.' + sig;
}

function parseToken(token) {
  try {
    if (!token) return null;
    const [payload, sig] = token.split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', tokenSecret()).update(payload).digest('hex');
    const a = Buffer.from(sig, 'hex'), b = Buffer.from(expected, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const [userId, email, exp] = Buffer.from(payload, 'base64url').toString('utf8').split(':');
    if (!exp || Date.now() > parseInt(exp)) return null;
    return { userId: parseInt(userId), email };
  } catch (e) {
    return null;
  }
}

function adminEmails() {
  return (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
}
function isAdminUser(user) {
  return !!user && adminEmails().includes((user.email || '').toLowerCase());
}
function userPayload(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    freeReportsUsed: u.free_reports_used,
    paidCredits: u.paid_credits,
    freeRemaining: Math.max(0, 2 - u.free_reports_used),
    totalReports: u.total_reports_generated,
    isAdmin: isAdminUser(u)
  };
}

async function getUserFromToken(token) {
  const parsed = parseToken(token);
  if (!parsed) return null;
  const result = await pool.query('SELECT * FROM users WHERE id = $1 AND LOWER(email) = LOWER($2)', [parsed.userId, parsed.email]);
  return result.rows[0] || null;
}

// ── BUNDLE DEFINITIONS ──
const BUNDLES = {
  single:       { name: 'Single Report',       reports: 1,  amount: 250000  }, // ₦2,500
  starter:      { name: 'Starter Bundle',      reports: 10, amount: 2000000 }, // ₦20,000
  professional: { name: 'Professional Bundle', reports: 30, amount: 5100000 }, // ₦51,000
  assessor:     { name: 'Assessor Bundle',     reports: 50, amount: 7000000 }  // ₦70,000
};

// ══════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, phone, nbte_number, password, skill_areas } = req.body;
  const email = (req.body.email || '').trim().toLowerCase();
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required' });
  }
  try {
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    const hash = hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, nbte_number, skill_areas, password_hash) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, email, free_reports_used, paid_credits, total_reports_generated',
      [name, email, phone || null, nbte_number || null, Array.isArray(skill_areas) ? skill_areas : [], hash]
    );
    const user = result.rows[0];
    const token = generateToken(user.id, user.email);
    res.json({ success: true, token, user: userPayload(user) });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const hash = hashPassword(password);
    const result = await pool.query(
      'SELECT id, name, email, free_reports_used, paid_credits, total_reports_generated FROM users WHERE LOWER(email) = $1 AND password_hash = $2',
      [email, hash]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = result.rows[0];
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = generateToken(user.id, user.email);
    res.json({ success: true, token, user: userPayload(user) });
  } catch (err) {
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// Get current user
app.get('/api/auth/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user: userPayload(user) });
});

// ── Send email through Brevo (needs BREVO_API_KEY + BREVO_SENDER_EMAIL) ──
async function sendEmail(to, subject, html) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_SENDER_EMAIL) return false;
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: 'QAA Assessor Tool', email: process.env.BREVO_SENDER_EMAIL },
        to: [{ email: to }],
        subject,
        htmlContent: html
      })
    });
    return r.ok;
  } catch (e) {
    console.error('Email error:', e.message);
    return false;
  }
}

// Forgot password — always returns the same message so emails cannot be probed
app.post('/api/auth/forgot', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const generic = { success: true, message: 'If an account exists for that email, a reset link has been sent. Check your inbox and spam folder.' };
  if (!email) return res.status(400).json({ error: 'Enter your email address' });
  try {
    const u = await pool.query('SELECT id, name, email FROM users WHERE LOWER(email) = $1', [email]);
    if (!u.rows.length) return res.json(generic);
    const user = u.rows[0];
    const recent = await pool.query("SELECT 1 FROM password_resets WHERE user_id = $1 AND created_at > NOW() - INTERVAL '60 seconds'", [user.id]);
    if (recent.rows.length) return res.json(generic);
    const raw = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [user.id]);
    await pool.query("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1,$2, NOW() + INTERVAL '1 hour')", [user.id, tokenHash]);
    const link = (process.env.APP_URL || 'https://nsq-assessor-tool.netlify.app') + '/?reset=' + raw;
    await sendEmail(user.email, 'Reset your QAA Assessor Tool password',
      `<p>Hello ${String(user.name).replace(/[<>&"]/g, '')},</p><p>Click the link below to set a new password. It expires in 1 hour.</p><p><a href="${link}">Reset my password</a></p><p>If you did not ask for this, ignore this email.</p>`);
    res.json(generic);
  } catch (err) {
    res.status(500).json({ error: 'Could not process request' });
  }
});

// Reset password with emailed token
app.post('/api/auth/reset', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 6) {
    return res.status(400).json({ error: 'A valid link and a password of at least 6 characters are required' });
  }
  try {
    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    const r = await pool.query('SELECT user_id FROM password_resets WHERE token_hash = $1 AND expires_at > NOW()', [tokenHash]);
    if (!r.rows.length) return res.status(400).json({ error: 'This reset link is invalid or has expired. Please request a new one.' });
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashPassword(password), r.rows[0].user_id]);
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [r.rows[0].user_id]);
    res.json({ success: true, message: 'Password updated. You can now sign in.' });
  } catch (err) {
    res.status(500).json({ error: 'Could not reset password' });
  }
});

// ══════════════════════════════════════════════
// CLAUDE API ROUTE — WITH CREDIT GATING
// ══════════════════════════════════════════════
app.post('/api/claude', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const { messages, system, reportType, skill, unitNumber } = req.body;

  // Authenticate
  const user = await getUserFromToken(token);
  if (!user) {
    return res.status(401).json({ error: 'Please log in to generate reports' });
  }

  const isAdmin = isAdminUser(user);

  // Check credits (admin accounts are unlimited)
  const freeRemaining = Math.max(0, 2 - user.free_reports_used);
  const hasFreeCredits = freeRemaining > 0;
  const hasPaidCredits = user.paid_credits > 0;

  if (!isAdmin && !hasFreeCredits && !hasPaidCredits) {
    return res.status(402).json({
      error: 'INSUFFICIENT_CREDITS',
      message: 'You have used all your free reports. Please purchase a bundle to continue.',
      freeRemaining: 0,
      paidCredits: 0
    });
  }

  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await client.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 4000,
      system: system || 'You are a certified NSQ Quality Assurance Assessor.',
      messages: messages || [{ role: 'user', content: req.body.prompt || '' }]
    });

    const text = response.content.map(b => b.text || '').join('');

    // Deduct credit
    const creditType = isAdmin ? 'admin' : (hasFreeCredits ? 'free' : 'paid');
    if (isAdmin) {
      await pool.query('UPDATE users SET total_reports_generated = total_reports_generated + 1 WHERE id = $1', [user.id]);
    } else if (hasFreeCredits) {
      await pool.query('UPDATE users SET free_reports_used = free_reports_used + 1, total_reports_generated = total_reports_generated + 1 WHERE id = $1', [user.id]);
    } else {
      await pool.query('UPDATE users SET paid_credits = paid_credits - 1, total_reports_generated = total_reports_generated + 1 WHERE id = $1', [user.id]);
    }

    // Log report
    await pool.query(
      'INSERT INTO report_logs (user_id, report_type, skill, unit_number, credit_type) VALUES ($1,$2,$3,$4,$5)',
      [user.id, reportType || 'unknown', skill || 'unknown', unitNumber || 'unknown', creditType]
    );

    // Return updated balance
    const updated = await pool.query('SELECT free_reports_used, paid_credits FROM users WHERE id = $1', [user.id]);
    const updatedUser = updated.rows[0];

    res.json({
      content: [{ type: 'text', text }],
      creditsRemaining: {
        freeRemaining: Math.max(0, 2 - updatedUser.free_reports_used),
        paidCredits: updatedUser.paid_credits,
        unlimited: isAdmin,
        creditUsed: creditType
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Generation failed: ' + err.message });
  }
});

// ══════════════════════════════════════════════
// PAYSTACK ROUTES
// ══════════════════════════════════════════════

// Initialise payment
app.post('/api/paystack/initiate', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  const { bundleKey } = req.body;
  const bundle = BUNDLES[bundleKey];
  if (!bundle) return res.status(400).json({ error: 'Invalid bundle selected' });

  const reference = 'QAA_' + user.id + '_' + Date.now();

  try {
    // Save pending transaction
    await pool.query(
      'INSERT INTO transactions (user_id, paystack_reference, bundle_name, reports_credited, amount_kobo, status) VALUES ($1,$2,$3,$4,$5,$6)',
      [user.id, reference, bundle.name, bundle.reports, bundle.amount, 'pending']
    );

    // Call Paystack initialize
    const paystackData = JSON.stringify({
      email: user.email,
      amount: bundle.amount,
      reference,
      metadata: {
        user_id: user.id,
        bundle_key: bundleKey,
        bundle_name: bundle.name,
        reports: bundle.reports
      },
      callback_url: 'https://nsq-assessor-tool.netlify.app'
    });

    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: '/transaction/initialize',
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(paystackData)
      }
    };

    const paystackRes = await new Promise((resolve, reject) => {
      const r = https.request(options, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resolve(JSON.parse(data)));
      });
      r.on('error', reject);
      r.write(paystackData);
      r.end();
    });

    if (!paystackRes.status) {
      return res.status(500).json({ error: 'Paystack error: ' + paystackRes.message });
    }

    res.json({
      success: true,
      authorizationUrl: paystackRes.data.authorization_url,
      reference,
      bundle: { name: bundle.name, reports: bundle.reports, amount: bundle.amount / 100 }
    });
  } catch (err) {
    res.status(500).json({ error: 'Payment initiation failed: ' + err.message });
  }
});

// Paystack webhook — payment confirmation
app.post('/api/paystack/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY).update(req.body).digest('hex');

  if (hash !== signature) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(req.body);

  if (event.event === 'charge.success') {
    const reference = event.data.reference;
    try {
      // Find transaction
      const txResult = await pool.query('SELECT * FROM transactions WHERE paystack_reference = $1 AND status = $2', [reference, 'pending']);
      if (!txResult.rows.length) return res.sendStatus(200);

      const tx = txResult.rows[0];

      // Credit user
      await pool.query('UPDATE users SET paid_credits = paid_credits + $1 WHERE id = $2', [tx.reports_credited, tx.user_id]);

      // Mark transaction complete
      await pool.query('UPDATE transactions SET status = $1, verified_at = NOW() WHERE paystack_reference = $2', ['success', reference]);

      console.log(`Payment verified: User ${tx.user_id} credited ${tx.reports_credited} reports`);
    } catch (err) {
      console.error('Webhook error:', err.message);
    }
  }

  res.sendStatus(200);
});

// Verify payment manually (called after redirect back from Paystack)
app.post('/api/paystack/verify', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  const { reference } = req.body;
  if (!reference) return res.status(400).json({ error: 'Reference required' });

  try {
    // Check if already verified
    const txCheck = await pool.query('SELECT * FROM transactions WHERE paystack_reference = $1', [reference]);
    if (txCheck.rows.length && txCheck.rows[0].status === 'success') {
      const updated = await pool.query('SELECT paid_credits, free_reports_used FROM users WHERE id = $1', [user.id]);
      return res.json({
        success: true,
        alreadyVerified: true,
        paidCredits: updated.rows[0].paid_credits,
        freeRemaining: Math.max(0, 2 - updated.rows[0].free_reports_used)
      });
    }

    // Verify with Paystack
    const options = {
      hostname: 'api.paystack.co',
      port: 443,
      path: `/transaction/verify/${reference}`,
      method: 'GET',
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` }
    };

    const paystackRes = await new Promise((resolve, reject) => {
      const r = https.request(options, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resolve(JSON.parse(data)));
      });
      r.on('error', reject);
      r.end();
    });

    if (paystackRes.data?.status === 'success') {
      const tx = txCheck.rows[0];
      if (tx && tx.status === 'pending') {
        await pool.query('UPDATE users SET paid_credits = paid_credits + $1 WHERE id = $2', [tx.reports_credited, user.id]);
        await pool.query('UPDATE transactions SET status = $1, verified_at = NOW() WHERE paystack_reference = $2', ['success', reference]);
      }
      const updated = await pool.query('SELECT paid_credits, free_reports_used FROM users WHERE id = $1', [user.id]);
      res.json({
        success: true,
        paidCredits: updated.rows[0].paid_credits,
        freeRemaining: Math.max(0, 2 - updated.rows[0].free_reports_used)
      });
    } else {
      res.status(400).json({ error: 'Payment not confirmed by Paystack' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Verification failed: ' + err.message });
  }
});

// Get transaction history
app.get('/api/transactions', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });

  const result = await pool.query(
    'SELECT bundle_name, reports_credited, amount_kobo, status, created_at, verified_at FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20',
    [user.id]
  );
  res.json({ transactions: result.rows });
});

// ══════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════
// Shared admin gate: returns the user if allowed, otherwise sends a specific error
async function adminGate(req, res) {
  if (!process.env.ADMIN_PASSWORD) {
    res.status(503).json({ error: 'ADMIN_PASSWORD is not set on the server (add it in Railway Variables)' });
    return null;
  }
  if (req.headers['x-admin-key'] !== process.env.ADMIN_PASSWORD) {
    res.status(403).json({ error: 'Incorrect admin password' });
    return null;
  }
  const user = await getUserFromToken(req.headers.authorization?.replace('Bearer ', ''));
  if (!user) {
    res.status(401).json({ error: 'Your sign-in has expired. Sign out, sign in again, then retry' });
    return null;
  }
  if (adminEmails().length && !isAdminUser(user)) {
    res.status(403).json({ error: 'This account (' + user.email + ') is not listed in ADMIN_EMAILS' });
    return null;
  }
  return user;
}

app.get('/api/admin/stats', async (req, res) => {
  const adminUser = await adminGate(req, res);
  if (!adminUser) return;

  try {
    // Summary stats
    const statsResult = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM users)::int as "totalUsers",
        (SELECT COALESCE(SUM(total_reports_generated),0) FROM users)::int as "totalReports",
        (SELECT COALESCE(SUM(amount_kobo),0) FROM transactions WHERE status='success')::int as "totalRevenue",
        (SELECT COUNT(*) FROM report_logs WHERE created_at > NOW() - INTERVAL '1 day')::int as "todayReports",
        (SELECT COUNT(DISTINCT user_id) FROM report_logs WHERE created_at > NOW() - INTERVAL '7 days')::int as "activeThisWeek",
        (SELECT COUNT(*) FROM transactions WHERE status='success')::int as "paidTransactions"
    `);

    // All users
    const usersResult = await pool.query(`
      SELECT id, name, email, phone, nbte_number, skill_areas, free_reports_used, paid_credits, 
             total_reports_generated, created_at, last_login
      FROM users ORDER BY created_at DESC
    `);

    // Skill usage
    const skillResult = await pool.query(`
      SELECT skill, COUNT(*) as count 
      FROM report_logs 
      WHERE skill != 'unknown' 
      GROUP BY skill 
      ORDER BY count DESC 
      LIMIT 10
    `);

    // Recent transactions with user names
    const txResult = await pool.query(`
      SELECT t.bundle_name, t.reports_credited, t.amount_kobo, t.status, t.created_at,
             u.name as user_name, u.email as user_email
      FROM transactions t
      LEFT JOIN users u ON t.user_id = u.id
      ORDER BY t.created_at DESC LIMIT 20
    `);

    // Recent report logs with user names
    const logsResult = await pool.query(`
      SELECT l.report_type, l.skill, l.unit_number, l.credit_type, l.created_at,
             u.name as user_name
      FROM report_logs l
      LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC LIMIT 30
    `);

    res.json({
      stats: statsResult.rows[0],
      users: usersResult.rows,
      skillUsage: skillResult.rows,
      transactions: txResult.rows,
      reportLogs: logsResult.rows
    });
  } catch (err) {
    res.status(500).json({ error: 'Admin data error: ' + err.message });
  }
});

// Health check
// Admin: record a manual (bank transfer) payment and add credits
app.post('/api/admin/add-credits', async (req, res) => {
  const adminUser = await adminGate(req, res);
  if (!adminUser) return;
  const email = (req.body.email || '').trim().toLowerCase();
  const bundle = BUNDLES[req.body.bundleKey];
  if (!email || !bundle) return res.status(400).json({ error: 'A user email and a valid bundle are required' });
  const note = String(req.body.note || '').replace(/[^\w\s\-\/.,]/g, '').trim().slice(0, 60);
  try {
    const u = await pool.query('SELECT id, name, email FROM users WHERE LOWER(email) = $1', [email]);
    if (!u.rows.length) return res.status(404).json({ error: 'No user registered with that email' });
    const user = u.rows[0];
    const reference = 'MANUAL-' + Date.now() + '-' + crypto.randomBytes(2).toString('hex') + (note ? ' ' + note : '');
    await pool.query(
      "INSERT INTO transactions (user_id, paystack_reference, bundle_name, reports_credited, amount_kobo, status, verified_at) VALUES ($1,$2,$3,$4,$5,'success',NOW())",
      [user.id, reference, bundle.name + ' (manual)', bundle.reports, bundle.amount]
    );
    const upd = await pool.query('UPDATE users SET paid_credits = paid_credits + $1 WHERE id = $2 RETURNING paid_credits', [bundle.reports, user.id]);
    res.json({ success: true, name: user.name, email: user.email, added: bundle.reports, paidCredits: upd.rows[0].paid_credits, reference });
  } catch (err) {
    res.status(500).json({ error: 'Could not add credits: ' + err.message });
  }
});

// Admin: set a temporary password for a user (fallback when email reset is not configured)
app.post('/api/admin/reset-password', async (req, res) => {
  const adminUser = await adminGate(req, res);
  if (!adminUser) return;
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    const temp = crypto.randomBytes(5).toString('hex');
    const r = await pool.query('UPDATE users SET password_hash = $1 WHERE LOWER(email) = $2 RETURNING email', [hashPassword(temp), email]);
    if (!r.rows.length) return res.status(404).json({ error: 'No user with that email' });
    res.json({ success: true, email: r.rows[0].email, tempPassword: temp });
  } catch (err) {
    res.status(500).json({ error: 'Reset failed' });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`QAA API Server running on port ${PORT}`));
