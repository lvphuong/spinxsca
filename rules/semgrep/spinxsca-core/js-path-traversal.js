const fs = require('fs');
const path = require('path');

app.get('/a', (req, res) => {
  // ruleid: js-path-traversal
  res.sendFile(path.join(__dirname, 'uploads', req.query.name));
});

app.get('/b/:file', (req, res) => {
  const target = path.resolve('/srv/data', req.params.file);
  // ruleid: js-path-traversal
  fs.readFile(target, 'utf8', (err, data) => res.send(data));
});

app.get('/c', (req, res) => {
  const file = path.resolve('/srv/reports', path.basename(req.query.name));
  // ok: js-path-traversal
  res.sendFile(file);
});

app.get('/d', (req, res) => {
  // ok: js-path-traversal
  fs.readFile('/etc/app/config.json', 'utf8', () => {});
});
