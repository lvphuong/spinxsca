const express = require('express');
const { requireAuth } = require('./auth');
const orders = require('./routes/orders');

const app = express();
app.use(express.json());
app.use(requireAuth);
app.use('/api', orders);
module.exports = app;
