const express = require('express');
const _ = require('lodash');

const app = express();

// Renders a user-supplied template: lodash.template compiles it into code (GHSA-35jh-r3h4-6jhm).
app.get('/preview', (req, res) => {
  const render = _.template(req.query.t);
  res.send(render({ user: req.query.user }));
});

module.exports = app;
