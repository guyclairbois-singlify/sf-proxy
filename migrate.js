const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS package_keys (
      org_id       VARCHAR(18)  PRIMARY KEY,
      key_hash     VARCHAR(64)  NOT NULL,
      status       VARCHAR(10)  NOT NULL DEFAULT 'active',
      created_at   TIMESTAMP    NOT NULL,
      last_used_at TIMESTAMP
    )
  `);
  console.log('Migration complete.');
  await pool.end();
}
migrate().catch(err => { console.error(err); process.exit(1); });

