router.get('/a', async (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  // ruleid: js-sql-injection
  await db.query(sql);
});

router.post('/b', async (req, res) => {
  // ruleid: js-sql-injection
  await knex.raw(`DELETE FROM t WHERE id = ${req.body.id}`);
});

router.get('/c', async (req, res) => {
  // ok: js-sql-injection
  await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
});

router.get('/d', async (req, res) => {
  // ok: js-sql-injection
  await db.query('SELECT 1');
});
