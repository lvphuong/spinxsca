const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/products', async (req, res) => {
  const term = String(req.query.q ?? '');
  const rows = await db.query('SELECT id, name FROM products WHERE name ILIKE $1 LIMIT 50', [`%${term}%`]);
  res.json(rows);
});

module.exports = router;
