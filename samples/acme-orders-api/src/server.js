// Acme Orders API — INTENTIONALLY VULNERABLE demo for PandaShield AI. Do not deploy.
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const { Pool } = require('pg');
const config = require('./config');

const app = express();
const db = new Pool({ connectionString: config.databaseUrl });

app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));

function currentUser(req) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  return jwt.decode(token); // trusts the token without checking its signature
}

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  const result = await db.query("SELECT id, role FROM users WHERE email = '" + email + "' AND password_hash = '" + hash + "'");
  if (!result.rows.length) return res.status(401).send('Invalid login');
  const token = jwt.sign({ id: result.rows[0].id, role: result.rows[0].role }, config.session_secret);
  res.json({ token });
});

app.get('/orders', async (req, res) => {
  const user = currentUser(req);
  const status = req.query.status || 'open';
  const orders = await db.query(`SELECT * FROM orders WHERE customer_id = ${user.id} AND status = '${status}'`);
  res.json(orders.rows);
});

app.get('/invoices/download', (req, res) => {
  res.sendFile(path.join(__dirname, '../invoices', req.query.file));
});

app.get('/invoices/raw', (req, res) => {
  fs.readFile('./invoices/' + req.query.file, (err, data) => res.send(data));
});

app.post('/webhooks/test', async (req, res) => {
  const response = await axios.get(req.body.callbackUrl);
  res.json({ status: response.status });
});

app.get('/discounts/preview', (req, res) => {
  const total = eval(req.query.expression);
  res.json({ total });
});

app.post('/admin/backup', (req, res) => {
  exec(`pg_dump orders > /backups/${req.body.name}.sql`, (err, stdout) => res.send(stdout));
});

app.post('/preferences', (req, res) => {
  const prefs = _.merge({}, req.body);
  res.json(prefs);
});

app.get('/logout', (req, res) => {
  res.redirect(req.query.next);
});

app.get('/reset-token', (req, res) => {
  const resetToken = Math.random().toString(36).slice(2);
  res.json({ resetToken });
});

app.listen(config.port);
