const { exec, execFile } = require('child_process');

app.get('/a', (req, res) => {
  // ruleid: js-command-injection
  exec('ping -c 1 ' + req.query.host, () => {});
});

app.get('/b', (req, res) => {
  // ok: js-command-injection
  execFile('ping', ['-c', '1', req.query.host], () => {});
});

app.get('/c', (req, res) => {
  const re = /x/;
  // ok: js-command-injection
  re.exec(req.query.text);
});
