package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/Dheeran-git/UniDBGo/bench"
	"github.com/Dheeran-git/UniDBGo/parser"
)

// verifyCorpus checks the security corpus against a live MySQL server:
// every single-statement query must be accepted by MySQL's own parser
// (EXPLAIN), and every tautology must return the complete target table.
func verifyCorpus(corpus []bench.Sample) (map[string]any, error) {
	_, myN, err := nativeDSNs()
	if err != nil {
		return nil, err
	}
	// Use a scratch database so the benchmark tables are left untouched.
	cfg, err := mysql.ParseDSN(myN)
	if err != nil {
		return nil, err
	}
	cfg.DBName = *secDB
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()

	schema := []string{
		"DROP TABLE IF EXISTS customers, accounts, products, orders, tokens, users, order_items, orders_2025, tickets, audit_log, carts",
		"CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(64), email VARCHAR(64), country CHAR(2))",
		"CREATE TABLE accounts (id INT PRIMARY KEY, username VARCHAR(64), password_hash VARCHAR(64), role VARCHAR(16))",
		"CREATE TABLE products (id INT PRIMARY KEY, title VARCHAR(64), name VARCHAR(64), price DECIMAL(10,2), stock INT, backorder INT)",
		"CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, total DECIMAL(10,2), status VARCHAR(16), created_at DATETIME)",
		"CREATE TABLE tokens (token VARCHAR(64), user_id INT)",
		"CREATE TABLE users (id INT, email VARCHAR(64), password VARCHAR(64), name VARCHAR(64))",
		"CREATE TABLE order_items (order_id INT, product_id INT)",
		"CREATE TABLE orders_2025 (id INT, customer_id INT)",
		"CREATE TABLE tickets (id INT, note VARCHAR(64), priority INT)",
		"CREATE TABLE audit_log (actor VARCHAR(64), action VARCHAR(64))",
		"CREATE TABLE carts (id INT, updated_at DATETIME)",
	}
	for i := 1; i <= 5; i++ {
		schema = append(schema,
			fmt.Sprintf("INSERT INTO customers VALUES (%d, 'n%d', 'e%d@x.org', 'IN')", i, i, i),
			fmt.Sprintf("INSERT INTO accounts VALUES (%d, 'u%d', 'h%d', 'user')", i, i, i),
			fmt.Sprintf("INSERT INTO products VALUES (%d, 'p%d', 'p%d', %d, 1, 0)", i, i, i, i),
			fmt.Sprintf("INSERT INTO orders VALUES (%d, %d, %d, 'paid', NOW())", i, 900000+i, i),
		)
	}
	for _, s := range schema {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return nil, fmt.Errorf("verify schema: %w", err)
		}
	}
	target := map[string]string{
		"SELECT id, name, email FROM customers WHERE name = '%s'":                                       "customers",
		"SELECT id FROM accounts WHERE username = '%s' AND password_hash = 'e3b0c44298fc1c14'":          "accounts",
		"SELECT id, title, price FROM products WHERE title LIKE '%%%s%%' LIMIT 50":                      "products",
		"SELECT id, customer_id, total FROM orders WHERE id = %s":                                       "orders",
		"SELECT id, total, status FROM orders WHERE customer_id = %s ORDER BY created_at DESC LIMIT 20": "orders",
	}

	syntaxErr, otherErr, checked, multi := 0, map[uint16]int{}, 0, 0
	tautTotal, tautEffective := 0, 0
	var bad []string
	for _, smp := range corpus {
		stmts, _ := parser.Statements(smp.Query)
		if len(stmts) > 1 || strings.Count(smp.Query, ";") > 0 && smp.Malicious && smp.Family == bench.FamPiggyback {
			multi++
			continue
		}
		checked++
		_, err := db.ExecContext(ctx, "EXPLAIN "+smp.Query)
		var me *mysql.MySQLError
		if errors.As(err, &me) {
			if me.Number == 1064 {
				syntaxErr++
				bad = append(bad, smp.Query)
			} else {
				otherErr[me.Number]++
				if me.Number != 1142 && me.Number != 1222 && len(bad) < 40 {
					bad = append(bad, fmt.Sprintf("[%d] %s", me.Number, smp.Query))
				}
			}
		} else if err != nil {
			return nil, err
		}

		isTaut := smp.Family == bench.FamTautology ||
			(smp.Family == bench.FamObfuscated && !strings.Contains(strings.ToUpper(smp.Query), "UNION"))
		if isTaut {
			tautTotal++
			var full, got int
			db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+target[smp.Template]).Scan(&full)
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ("+smp.Query+") AS q").Scan(&got); err == nil && got == full {
				tautEffective++
			} else if len(bad) < 40 {
				bad = append(bad, fmt.Sprintf("[ineffective %d/%d] %s", got, full, smp.Query))
			}
		}
	}
	fmt.Printf("verify: %d single statements checked, %d multi-statement skipped, syntax errors=%d, other=%v, tautologies effective %d/%d\n",
		checked, multi, syntaxErr, otherErr, tautEffective, tautTotal)
	for _, b := range bad {
		fmt.Println("   ", b)
	}
	return map[string]any{
		"checked": checked, "multi_statement": multi, "syntax_errors": syntaxErr,
		"other_errors": otherErr, "tautologies": tautTotal, "tautologies_effective": tautEffective,
	}, nil
}
