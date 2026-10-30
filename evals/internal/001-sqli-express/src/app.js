const express = require('express');
const users = require('./routes/users');

const app = express();
app.use(express.json());
app.use('/api', users);

app.listen(3000);
