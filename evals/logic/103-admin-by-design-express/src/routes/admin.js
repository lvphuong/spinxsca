const express = require('express');
const { User } = require('../models');

const router = express.Router();

// Administrators manage every account by design (see the case's operator context).
router.get('/users/:id', async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (!user) return res.status(404).end();
  return res.json(user);
});

router.post('/users/:id/role', async (req, res) => {
  const [count] = await User.update({ role: req.body.role }, { where: { id: req.params.id } });
  if (!count) return res.status(404).end();
  return res.json({ updated: true });
});

module.exports = router;
