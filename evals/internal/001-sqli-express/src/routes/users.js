const express = require('express');
const db = require('../db');

const router = express.Router();

// Vulnerable: request input concatenated into SQL.
router.get('/users/search', async (req, res) => {
  const name = req.query.name;
  const sql = "SELECT id, email FROM users WHERE name = '" + name + "'";
  const rows = await db.query(sql);
  res.json(rows);
});

// Safe: parameterized query.
router.get('/users/:id', async (req, res) => {
  const rows = await db.query('SELECT id, email FROM users WHERE id = $1', [req.params.id]);
  res.json(rows[0] ?? null);
});

// Vulnerable: request body interpolated into a template literal.
router.delete('/users', async (req, res) => {
  await db.query(`DELETE FROM users WHERE email = '${req.body.email}'`);
  res.status(204).end();
});

module.exports = router;
