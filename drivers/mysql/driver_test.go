package mysql

import (
	"testing"
	"time"

	"github.com/Dheeran-git/UniDBGo/internal"
)

func TestConfig(t *testing.T) {
	cfg, err := Config(internal.Config{
		Host: "db.example", Port: 3306, Database: "shop",
		Username: "app", Password: "p:ss@w/rd",
		Params: map[string]string{"parseTime": "true", "timeout": "3s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "app" || cfg.Passwd != "p:ss@w/rd" || cfg.Addr != "db.example:3306" || cfg.DBName != "shop" {
		t.Errorf("unexpected config %+v", cfg)
	}
	if !cfg.ParseTime || cfg.Timeout != 3*time.Second {
		t.Errorf("parameters not applied: parseTime=%v timeout=%v", cfg.ParseTime, cfg.Timeout)
	}
	if _, err := Config(internal.Config{Params: map[string]string{"parseTime": "maybe"}}); err == nil {
		t.Error("invalid parameter accepted")
	}
}
