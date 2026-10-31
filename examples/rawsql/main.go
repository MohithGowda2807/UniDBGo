package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func main() {

	// Connect PostgreSQL
	pgDB, _ := sql.Open(
		"postgres",
		"host=localhost port=5432 user=postgres password=pass dbname=demo sslmode=disable",
	)

	// Connect MySQL
	myDB, _ := sql.Open(
		"mysql",
		"root:pass@tcp(localhost:3307)/demo",
	)

	// PostgreSQL query
	pgRows, _ := pgDB.Query(
		"SELECT id, name FROM users WHERE city = $1",
		"Bengaluru",
	)

	type User struct {
		ID   int
		Name string
	}

	var users []User

	for pgRows.Next() {
		var u User
		pgRows.Scan(&u.ID, &u.Name)
		users = append(users, u)
	}

	// MySQL query
	myRows, _ := myDB.Query(
		"SELECT user_id, total FROM orders WHERE status = ?",
		"paid",
	)

	type Order struct {
		UserID int
		Total  float64
	}

	var orders []Order

	for myRows.Next() {
		var o Order
		myRows.Scan(&o.UserID, &o.Total)
		orders = append(orders, o)
	}

	// Manual join
	fmt.Println("Raw Go Manual Join:")

	for _, u := range users {
		for _, o := range orders {
			if u.ID == o.UserID {
				fmt.Println(u.Name, o.Total)
			}
		}
	}
}
