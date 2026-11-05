const express = require('express');
const { requireAuth } = require('./middleware/auth');
const account = require('./routes/account');

const app = express();
app.use(express.json());
app.use(requireAuth);
app.use('/api', account);
module.exports = app;
