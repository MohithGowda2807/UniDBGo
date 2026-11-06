// Command eval-sqlmap runs a deliberately vulnerable HTTP application that
// builds SQL by string concatenation, so that the external tool sqlmap can be
// pointed at it. It exists only to evaluate UniDB-Go's security engine against
// an independently generated attack corpus; it must never be exposed.
//
// The app has three endpoints, one per injection context:
//
//	/account?id=<p>    numeric:  SELECT id, name, email FROM accounts WHERE id = <p>
//	/user?name=<p>     string:   SELECT id, name, email FROM accounts WHERE name = '<p>'
//	/search?q=<p>      LIKE:     SELECT id, name, email FROM accounts WHERE name LIKE '%<p>%'
//
// It backs onto a dedicated database (unidb_vuln) holding a small accounts
// table and a secret api_keys table, on either MySQL or PostgreSQL. It runs in
// one of two modes:
//
//	capture:   every built query is executed unprotected (as a typical
//	           vulnerable app would) and appended, with its raw parameter value
//	           and endpoint, to a JSONL log. This is what sqlmap exploits and
//	           what later feeds the offline detector evaluation.
//	protected: every built query is first analysed by UniDB-Go's security
//	           engine (security.AnalyzeFor with the backend's dialect and
//	           api_keys restricted). Blocked queries are not executed; the app
//	           returns a generic error page.
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/security"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

var (
	backend  = flag.String("backend", "mysql", "backend: mysql or postgres")
	mode     = flag.String("mode", "capture", "mode: capture (unprotected, logged) or protected (security engine)")
	addr     = flag.String("addr", "127.0.0.1:8099", "listen address")
	logPath  = flag.String("log", "", "JSONL capture log path (append); required in capture mode")
	myDSN    = flag.String("mysql-dsn", "vuln:pass@tcp(127.0.0.1:3306)/unidb_vuln?multiStatements=true", "MySQL database/sql DSN")
	pgDSN    = flag.String("pg-dsn", "postgres://vuln:pass@127.0.0.1:5432/unidb_vuln?sslmode=disable", "PostgreSQL database/sql DSN")
	restrict = flag.String("restrict", "api_keys", "comma-separated restricted tables for the security engine")
	tag      = flag.String("tag", "", "run tag stamped on every capture record (e.g. the sqlmap tamper/technique)")
	analyze  = flag.String("analyze", "", "comma-separated JSONL capture logs to evaluate offline instead of serving")
	outJSON  = flag.String("out", "", "output path for the offline analysis JSON")
)

// record is one line of the capture log.
type record struct {
	TS        string `json:"ts"`
	Tag       string `json:"tag,omitempty"`
	Backend   string `json:"backend"`
	Mode      string `json:"mode"`
	Endpoint  string `json:"endpoint"`
	ParamName string `json:"param_name"`
	ParamVal  string `json:"param_value"`
	Query     string `json:"query"`
	Blocked   bool   `json:"blocked"`
	Category  string `json:"category,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Executed  bool   `json:"executed"`
	Rows      int    `json:"rows"`
	DBError   string `json:"db_error,omitempty"`
}

type server struct {
	db      *sql.DB
	dialect parser.Dialect
	eng     *security.SecurityEngine
	protect bool

	mu  sync.Mutex
	enc *json.Encoder
}

func main() {
	flag.Parse()

	if *analyze != "" {
		if *outJSON == "" {
			log.Fatal("-analyze requires -out")
		}
		if err := runAnalyze(strings.Split(*analyze, ","), strings.Split(*restrict, ","), *outJSON); err != nil {
			log.Fatal(err)
		}
		return
	}

	var (
		db  *sql.DB
		err error
		dia parser.Dialect
	)
	switch *backend {
	case "mysql":
		db, err = sql.Open("mysql", *myDSN)
		dia = parser.MySQL
	case "postgres":
		db, err = sql.Open("postgres", *pgDSN)
		dia = parser.Postgres
	default:
		log.Fatalf("unknown backend %q", *backend)
	}
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("ping %s: %v", *backend, err)
	}

	srv := &server{
		db:      db,
		dialect: dia,
		eng:     security.NewSecurityEngine(strings.Split(*restrict, ",")...),
		protect: *mode == "protected",
	}
	if *mode == "capture" {
		if *logPath == "" {
			log.Fatal("capture mode requires -log")
		}
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("open log: %v", err)
		}
		defer f.Close()
		srv.enc = json.NewEncoder(f)
	}

	mux := http.NewServeMux()
	// Numeric context.
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("id")
		srv.handle(w, "/account", "id",
			fmt.Sprintf("SELECT id, name, email FROM accounts WHERE id = %s", p), p)
	})
	// Single-quoted string context.
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("name")
		srv.handle(w, "/user", "name",
			fmt.Sprintf("SELECT id, name, email FROM accounts WHERE name = '%s'", p), p)
	})
	// LIKE search context.
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("q")
		srv.handle(w, "/search", "q",
			fmt.Sprintf("SELECT id, name, email FROM accounts WHERE name LIKE '%%%s%%'", p), p)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })

	log.Printf("eval-sqlmap backend=%s mode=%s listening on %s", *backend, *mode, *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// handle builds a concatenated query for one endpoint and either executes it
// unprotected (capture) or runs it past the security engine first (protected).
func (s *server) handle(w http.ResponseWriter, endpoint, param, query, raw string) {
	rec := record{
		TS: time.Now().UTC().Format(time.RFC3339Nano), Tag: *tag, Backend: *backend, Mode: *mode,
		Endpoint: endpoint, ParamName: param, ParamVal: raw, Query: query,
	}

	if s.protect {
		dec := s.eng.AnalyzeFor(query, s.dialect)
		if dec.Block {
			rec.Blocked = true
			rec.Category = string(dec.Category)
			rec.Reason = dec.Reason
			s.write(rec)
			http.Error(w, "Request rejected", http.StatusForbidden)
			return
		}
	}

	rows, err := s.db.Query(query)
	rec.Executed = true
	if err != nil {
		rec.DBError = err.Error()
		s.write(rec)
		// A typical vulnerable app leaks the database error (error-based SQLi).
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString("<html><body><table>")
	cols, _ := rows.Columns()
	n := len(cols)
	for rows.Next() {
		cells := make([]any, n)
		ptrs := make([]any, n)
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		b.WriteString("<tr>")
		for _, c := range cells {
			fmt.Fprintf(&b, "<td>%s</td>", asText(c))
		}
		b.WriteString("</tr>")
		rec.Rows++
	}
	b.WriteString("</table></body></html>")
	s.write(rec)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, b.String())
}

// asText renders a scanned cell as a string for the HTML response.
func asText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// write appends one record to the capture log, if logging is enabled.
func (s *server) write(rec record) {
	if s.enc == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.enc.Encode(rec)
}
