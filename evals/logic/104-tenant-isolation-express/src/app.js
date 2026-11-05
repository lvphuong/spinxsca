const express = require('express');
const { requireAuth } = require('./auth');
const projects = require('./routes/projects');

const app = express();
app.use(express.json());
app.use(requireAuth);
app.use('/api', projects);
module.exports = app;
