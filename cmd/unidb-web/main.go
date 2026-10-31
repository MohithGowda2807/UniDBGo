// Command unidb-web serves the UniDB-Go dashboard.
//
// Without configuration it runs in demo mode. To execute queries against
// real databases, set UNIDB_SOURCES to a comma-separated list of name=URI
// pairs; the first source is the default:
//
//	UNIDB_SOURCES="postgres=postgres://u:p@localhost:5432/db,mysql=mysql://u:p@localhost:3306/db" unidb-web
package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/Dheeran-git/UniDBGo/web"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	e, err := web.EngineFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	mode := "demo mode (set UNIDB_SOURCES for live databases)"
	if e != nil {
		defer e.Close()
		mode = "live mode"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("UniDB-Go dashboard on http://localhost%s, %s", *addr, mode)
	if err := web.Run(ctx, *addr, e); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
