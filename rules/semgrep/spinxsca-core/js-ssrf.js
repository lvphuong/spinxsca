const axios = require('axios');

app.post('/a', async (req, res) => {
  // ruleid: js-ssrf
  await axios.post(req.body.callbackUrl, { ok: true });
});

app.get('/b', async (req, res) => {
  const target = req.query.url;
  // ruleid: js-ssrf
  const r = await fetch(target);
  res.send(await r.text());
});

app.get('/c', async (req, res) => {
  // ok: js-ssrf
  const r = await axios.get('https://api.example.com/search', { params: { q: req.query.q } });
  res.json(r.data);
});
