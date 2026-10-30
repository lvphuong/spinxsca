const axios = require('axios');
const express = require('express');

const router = express.Router();

// Vulnerable: the caller chooses where the server sends the request.
router.post('/webhooks/test', async (req, res) => {
  const response = await axios.post(req.body.callbackUrl, { event: 'ping' });
  res.json({ status: response.status });
});

// Vulnerable: URL preview fetches an arbitrary user-supplied URL.
router.get('/preview', async (req, res) => {
  const target = req.query.url;
  const page = await fetch(target);
  res.send(await page.text());
});

// Safe: fixed host; user input only becomes a query parameter.
router.get('/search', async (req, res) => {
  const response = await axios.get('https://api.example.com/search', { params: { q: req.query.q } });
  res.json(response.data);
});

module.exports = router;
