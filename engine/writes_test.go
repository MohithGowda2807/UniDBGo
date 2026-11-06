package engine

import (
	"context"
	"testing"

	"github.com/Dheeran-git/UniDBGo/security"
)

func TestCrossSourceWritesRejected(t *testing.T) {
	srcs, _ := testSources(t)
	e := &Engine{Sources: srcs, Default: "postgres", Security: security.NewSecurityEngine()}
	for _, q := range []string{
		"INSERT INTO mysql.archive SELECT id, note FROM postgres.events",
		"UPDATE mysql.orders SET flag = 1 WHERE user_id IN (SELECT id FROM postgres.users WHERE banned = 1)",
		"DELETE FROM orders WHERE user_id IN (SELECT id FROM mysql.users WHERE banned = 1)",
	} {
		if _, err := e.Exec(context.Background(), q); err == nil {
			t.Errorf("%s: want an error for a write that spans databases", q)
		}
	}
	for _, q := range []string{
		"INSERT INTO mysql.archive SELECT id, note FROM mysql.events",
		"UPDATE orders SET flag = 1 WHERE id = 3",
	} {
		if _, err := e.Exec(context.Background(), q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}
