const express = require('express');
const { Account } = require('../models');

const router = express.Router();

router.get('/account', async (req, res) => {
  const account = await Account.findOne({ where: { ownerId: req.user && req.user.id } });
  return res.json(account);
});

module.exports = router;
