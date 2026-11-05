const express = require('express');
const { Order } = require('../models');

const router = express.Router();

// Baseline: the lookup is scoped to the authenticated owner.
router.get('/orders/:id', async (req, res) => {
  const order = await Order.findOne({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!order) return res.status(404).end();
  return res.json(order);
});

// Sibling: the update is keyed by id alone, so any authenticated user can change any order.
router.put('/orders/:id', async (req, res) => {
  const [count] = await Order.update(
    { shippingAddress: req.body.shippingAddress, note: req.body.note },
    { where: { id: req.params.id } },
  );
  if (!count) return res.status(404).end();
  return res.json({ updated: true });
});

router.get('/orders', async (req, res) => {
  const orders = await Order.findAll({ where: { ownerId: req.user.id } });
  return res.json(orders);
});

module.exports = router;
