const { execFile } = require('node:child_process');
const path = require('node:path');
const express = require('express');

const router = express.Router();
const REPORT_DIR = path.resolve(__dirname, '../../reports');

router.get('/whois', (req, res) => {
  const domain = String(req.query.domain ?? '');
  if (!/^[a-z0-9.-]+$/i.test(domain)) return res.status(400).end();
  execFile('whois', [domain], (err, stdout) => {
    if (err) return res.status(500).end();
    res.type('text/plain').send(stdout);
  });
});

router.get('/reports/:name', (req, res) => {
  const file = path.resolve(REPORT_DIR, path.basename(req.params.name));
  if (!file.startsWith(REPORT_DIR + path.sep)) return res.status(400).end();
  res.sendFile(file);
});

module.exports = router;
