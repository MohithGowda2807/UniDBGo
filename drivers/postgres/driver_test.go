package postgres

import (
	"net/url"
	"testing"

	"github.com/Dheeran-git/UniDBGo/internal"
)

func TestDSN(t *testing.T) {
	dsn := DSN(internal.Config{
		Host: "db.example", Port: 5432, Database: "prod",
		Username: "app", Password: "p/ss@x:1?",
		Params: map[string]string{"sslmode": "verify-full", "application_name": "unidb"},
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if pw, _ := u.User.Password(); pw != "p/ss@x:1?" || u.User.Username() != "app" {
		t.Errorf("credentials not preserved: %s", dsn)
	}
	if u.Query().Get("sslmode") != "verify-full" || u.Query().Get("application_name") != "unidb" {
		t.Errorf("parameters not preserved: %s", dsn)
	}
	if u.Host != "db.example:5432" || u.Path != "/prod" {
		t.Errorf("address: %s", dsn)
	}
	d, _ := url.Parse(DSN(internal.Config{Host: "h", Port: 1}))
	if d.Query().Get("sslmode") != "disable" {
		t.Errorf("default sslmode missing: %s", d)
	}
}
