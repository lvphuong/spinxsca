const express = require('express');
const { Wallet, Refund } = require('../models');

const router = express.Router();

// Check-then-act without a transaction or conditional update: two concurrent refunds both pass the
// balance check and both are paid out.
router.post('/wallet/refund', async (req, res) => {
  const wallet = await Wallet.findOne({ where: { ownerId: req.user.id } });
  const amount = Number(req.body.amount);
  if (!(amount > 0) || wallet.balance < amount) return res.status(400).json({ error: 'insufficient funds' });
  await Refund.create({ walletId: wallet.id, amount });
  wallet.balance -= amount;
  await wallet.save();
  return res.json({ balance: wallet.balance });
});

router.get('/wallet', async (req, res) => {
  const wallet = await Wallet.findOne({ where: { ownerId: req.user.id } });
  return res.json(wallet);
});

module.exports = router;
