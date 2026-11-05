const express = require('express');
const { prisma } = require('../db');

const router = express.Router();

// Baseline: every list is filtered by the caller's tenant.
router.get('/projects', async (req, res) => {
  const projects = await prisma.project.findMany({ where: { tenantId: req.user.tenantId } });
  return res.json(projects);
});

// Sibling: the lookup by id has no tenant predicate, so a user of tenant A reads tenant B's project.
router.get('/projects/:id', async (req, res) => {
  const project = await prisma.project.findUnique({ where: { id: req.params.id } });
  if (!project) return res.status(404).end();
  return res.json(project);
});

router.post('/projects', async (req, res) => {
  const project = await prisma.project.create({ data: { name: req.body.name, tenantId: req.user.tenantId } });
  return res.status(201).json(project);
});

module.exports = router;
