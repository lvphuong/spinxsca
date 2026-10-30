const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const router = express.Router();
const UPLOAD_DIR = path.resolve(__dirname, '../../uploads');

// Vulnerable: the requested name can contain "../".
router.get('/files', (req, res) => {
  res.sendFile(path.join(UPLOAD_DIR, req.query.name));
});

// Vulnerable: path parameter flows into fs.readFile.
router.get('/notes/:file', (req, res) => {
  const target = path.resolve('/srv/notes', req.params.file);
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) return res.status(404).end();
    res.type('text/plain').send(data);
  });
});

// Safe: reduced to a file name and contained in the upload directory.
router.get('/avatars/:name', (req, res) => {
  const file = path.resolve(UPLOAD_DIR, path.basename(req.params.name));
  if (!file.startsWith(UPLOAD_DIR + path.sep)) return res.status(400).end();
  res.sendFile(file);
});

module.exports = router;
