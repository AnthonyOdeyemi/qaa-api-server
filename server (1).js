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
        password_hash VARCHAR(255) NOT NULL,
        free_reports_used INTEGER DEFAULT 0,
        paid_credits INTEGER DEFAULT 0,
        total_reports_generated INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        last_login TIMESTAMP
      );

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

function generateToken(userId, email) {
  const payload = `${userId}:${email}:${Date.now()}`;
  return crypto.createHash('sha256').update(payload + (process.env.TOKEN_SECRET || 'qaasecret2026')).digest('hex') + '.' + Buffer.from(`${userId}:${email}`).toString('base64');
}

function parseToken(token) {
  try {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const decoded = Buffer.from(parts[1], 'base64').toString('utf8');
    const [userId, email] = decoded.split(':');
    return { userId: parseInt(userId), email };
  } catch (e) {
    return null;
  }
}

async function getUserFromToken(token) {
  const parsed = parseToken(token);
  if (!parsed) return null;
  const result = await pool.query('SELECT * FROM users WHERE id = $1 AND email = $2', [parsed.userId, parsed.email]);
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
  const { name, email, phone, nbte_number, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required' });
  }
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    const hash = hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (name, email, phone, nbte_number, password_hash) VALUES ($1,$2,$3,$4,$5) RETURNING id, name, email, free_reports_used, paid_credits',
      [name, email, phone || null, nbte_number || null, hash]
    );
    const user = result.rows[0];
    const token = generateToken(user.id, user.email);
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        freeReportsUsed: user.free_reports_used,
        paidCredits: user.paid_credits,
        freeRemaining: Math.max(0, 2 - user.free_reports_used)
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const hash = hashPassword(password);
    const result = await pool.query(
      'SELECT id, name, email, free_reports_used, paid_credits, total_reports_generated FROM users WHERE email = $1 AND password_hash = $2',
      [email, hash]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = result.rows[0];
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = generateToken(user.id, user.email);
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        freeReportsUsed: user.free_reports_used,
        paidCredits: user.paid_credits,
        freeRemaining: Math.max(0, 2 - user.free_reports_used),
        totalReports: user.total_reports_generated
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// Get current user
app.get('/api/auth/me', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = await getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      freeReportsUsed: user.free_reports_used,
      paidCredits: user.paid_credits,
      freeRemaining: Math.max(0, 2 - user.free_reports_used),
      totalReports: user.total_reports_generated
    }
  });
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

  // Check credits
  const freeRemaining = Math.max(0, 2 - user.free_reports_used);
  const hasFreeCredits = freeRemaining > 0;
  const hasPaidCredits = user.paid_credits > 0;

  if (!hasFreeCredits && !hasPaidCredits) {
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
    const creditType = hasFreeCredits ? 'free' : 'paid';
    if (hasFreeCredits) {
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

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`QAA API Server running on port ${PORT}`));
