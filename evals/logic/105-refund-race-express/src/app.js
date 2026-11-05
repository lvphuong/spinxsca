const express = require('express');
const { requireAuth } = require('./auth');
const wallet = require('./routes/wallet');

const app = express();
app.use(express.json());
app.use(requireAuth);
app.use('/api', wallet);
module.exports = app;
