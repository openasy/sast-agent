async function find(db, req) {
  // ruleid: openasy.javascript.sql-injection
  await db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
  // ruleid: openasy.javascript.sql-injection
  await db.query("DELETE FROM users WHERE name = '" + req.body.name + "'");
  // ok: openasy.javascript.sql-injection
  await db.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  // ok: openasy.javascript.sql-injection
  await db.query(`SELECT * FROM orders`);
}
