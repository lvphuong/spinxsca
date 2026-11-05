const express = require('express');
const { requireAuth, requireRole } = require('./auth');
const admin = require('./routes/admin');

const app = express();
app.use(express.json());
app.use(requireAuth);
app.use('/admin', requireRole('admin'), admin);
module.exports = app;
