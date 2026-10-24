package main

import (
	"database/sql"
	"fmt"
)

func find(db *sql.DB, name string, id int) {
	// ruleid: openasy.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	// ruleid: openasy.go.sql-injection
	db.Exec(fmt.Sprintf("DELETE FROM orders WHERE id = %d", id))
	// ok: openasy.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = $1", name)
}
