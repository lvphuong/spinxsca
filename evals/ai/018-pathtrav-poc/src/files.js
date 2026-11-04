const fs = require('node:fs');
const path = require('node:path');

const BASE = path.join(__dirname, 'public');

/** Serves files from the public directory. */
function readPublic(name) {
  return fs.readFileSync(path.join(BASE, name), 'utf8');
}

function register(app) {
  app.get('/files', (req, res) => {
    res.send(fs.readFileSync(path.join(BASE, req.query.name), 'utf8'));
  });
}

module.exports = { readPublic, register };
