def find(cur, name, order_id):
    # ruleid: openasy.python.sql-injection
    cur.execute(f"SELECT * FROM orders WHERE id = {order_id}")
    # ruleid: openasy.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: openasy.python.sql-injection
    cur.execute("DELETE FROM users WHERE name = '" + name + "'")
    # ok: openasy.python.sql-injection
    cur.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
