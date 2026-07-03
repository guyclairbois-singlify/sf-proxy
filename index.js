const express             = require('express');
const { Pool }            = require('pg');
const crypto              = require('crypto');
const { HttpsProxyAgent } = require('https-proxy-agent');

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}
function generateKey() {
  return crypto.randomBytes(32).toString('hex');
}

// POST /register -----------------------------------------------
// Called once per package install to issue a key for that org.
// Protected by the REGISTER_SECRET environment variable.
app.post('/register', async (req, res) => {
  if (req.headers['x-register-secret'] !== process.env.REGISTER_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { org_id } = req.body;
  if (!org_id) return res.status(400).json({ error: 'org_id required' });
  try {
    const existing = await pool.query(
      'SELECT 1 FROM package_keys WHERE org_id = $1', [org_id]
    );
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Org already registered' });

    const key     = generateKey();
    const keyHash = hashKey(key);
	await pool.query(
      `INSERT INTO package_keys (org_id, key_hash, status, created_at) VALUES ($1, $2, 'active', NOW())`,
      [org_id, keyHash]
    );
    res.json({ api_key: key }); // Returned once — never stored in plain form
  } catch (err) {
    console.error('[register]', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /proxy --------------------------------------------------
// Validates the package key, then relays the call to the
// third-party API through QuotaGuard's static egress IP.
app.post('/proxy', async (req, res) => {
  const packageKey = req.headers['x-package-key'];
  if (!packageKey) return res.status(401).json({ error: 'Missing X-Package-Key' });

  const { target_url, method, headers: fwdHeaders, body: fwdBody } = req.body;
  if (!target_url) return res.status(400).json({ error: 'target_url required' });

  try {
	const result = await pool.query(
      `UPDATE package_keys SET last_used_at = NOW() WHERE key_hash = $1 AND status = 'active' RETURNING org_id`,
      [hashKey(packageKey)]
    );
    if (result.rows.length === 0)
      return res.status(401).json({ error: 'Invalid or revoked key' });

    const agent    = new HttpsProxyAgent(process.env.QUOTAGUARDSTATIC_URL);
    const response = await fetch(target_url, {
      method:     method || 'GET',
      headers:    fwdHeaders || {},
      body:       fwdBody ? JSON.stringify(fwdBody) : undefined,
      dispatcher: agent,
    });

    const text = await response.text();
    res.status(response.status)
       .set('Content-Type', response.headers.get('content-type') || 'application/json')
       .send(text);

  } catch (err) {
    console.error('[proxy]', err.message);
    res.status(502).json({ error: 'Bad gateway' });
  }
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy listening on port ${PORT}`));

