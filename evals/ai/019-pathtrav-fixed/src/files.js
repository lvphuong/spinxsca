const fs = require('node:fs');
const path = require('node:path');

const BASE = path.join(__dirname, 'public');

/** Serves files from the public directory; names are resolved and contained. */
function readPublic(name) {
  const target = path.resolve(BASE, name);
  if (!target.startsWith(BASE + path.sep)) throw new Error('outside public');
  return fs.readFileSync(target, 'utf8');
}

function register(app) {
  app.get('/files', (req, res) => {
    res.send(readPublic(String(req.query.name)));
  });
}

module.exports = { readPublic, register };
