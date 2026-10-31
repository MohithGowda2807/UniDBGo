// Package web serves the UniDB-Go dashboard: a single-page UI and a small
// JSON API that runs queries through the pipeline and reports every stage.
package web

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/api"
	"github.com/Dheeran-git/UniDBGo/cache"
	"github.com/Dheeran-git/UniDBGo/engine"
	"github.com/Dheeran-git/UniDBGo/federation"
	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
	"github.com/Dheeran-git/UniDBGo/router"
	"github.com/Dheeran-git/UniDBGo/security"
)

//go:embed static
var staticFiles embed.FS

const (
	maxBodyBytes    = 1 << 20 // request bodies are small JSON documents
	maxResultRows   = 1000    // rows returned to the browser per query
	maxRouterProbes = 50      // queries per router demo request
	resultCacheTTL  = time.Minute
)

// PipelineResponse is what the frontend expects
type PipelineResponse struct {
	Query     string                 `json:"query"`
	AST       *parser.QueryAST       `json:"ast"`
	Plan      *planner.ExecutionPlan `json:"plan"`
	Decision  security.Decision      `json:"decision"`
	Results   []federation.Row       `json:"results,omitempty"`
	Truncated bool                   `json:"truncated,omitempty"`
	Metrics   PipelineMetrics        `json:"metrics"`
	Error     string                 `json:"error,omitempty"`
	CacheHit  bool                   `json:"cache_hit"`
	Mode      string                 `json:"mode"` // "live" or "demo"
}

type PipelineMetrics struct {
	ParseTimeMS    float64 `json:"parse_time_ms"`
	SecurityTimeMS float64 `json:"security_time_ms"`
	PlanTimeMS     float64 `json:"plan_time_ms"`
	ExecTimeMS     float64 `json:"exec_time_ms"`
	TotalTimeMS    float64 `json:"total_time_ms"`
}

type queryRequest struct {
	Query string `json:"query"`
}

// Router demo types
type aiRouterDemoRequest struct {
	Queries []string `json:"queries"`
}

type aiRouterPrediction struct {
	Query      string  `json:"query"`
	Database   string  `json:"database"`
	Dialect    string  `json:"dialect"`
	Confidence float64 `json:"confidence"`
}

type aiRouterDemoResponse struct {
	Predictions []aiRouterPrediction `json:"predictions"`
	TrainedOn   int                  `json:"trained_on"`
}

// Server is the dashboard. A nil Engine runs it in demo mode: parsing,
// security and planning are real, but rows are illustrative samples.
type Server struct {
	Engine   *engine.Engine
	Security *security.SecurityEngine

	cache  *cache.Engine
	router *router.RoutingModel
}

// NewServer creates a dashboard over e (nil for demo mode).
func NewServer(e *engine.Engine) *Server {
	sec := security.NewSecurityEngine()
	if e != nil && e.Security != nil {
		sec = e.Security
	}
	model := router.NewRoutingModel()
	model.Train(router.SeedData)
	return &Server{Engine: e, Security: sec, cache: cache.NewEngine(), router: model}
}

// Handler returns the HTTP handler serving the UI and the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/api/query", s.handleQuery)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/schema", s.handleSchema)
	mux.HandleFunc("/api/demo/ai-router", s.handleRouterDemo)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("unidb-web: encoding response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodePost reads a JSON POST body into v, enforcing method and size.
func decodePost(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON")
		}
		return false
	}
	return true
}

func (s *Server) mode() string {
	if s.Engine != nil {
		return "live"
	}
	return "demo"
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	var req queryRequest
	if !decodePost(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		writeError(w, http.StatusBadRequest, "query is empty")
		return
	}

	totalStart := time.Now()
	resp := PipelineResponse{Query: req.Query, Mode: s.mode()}
	finish := func() {
		resp.Metrics.TotalTimeMS = ms(time.Since(totalStart))
		writeJSON(w, http.StatusOK, resp)
	}

	// 1. Parser
	parseStart := time.Now()
	ast, parseErr := parser.Parse(req.Query)
	resp.Metrics.ParseTimeMS = ms(time.Since(parseStart))
	resp.AST = ast

	// 2. Security analysis on the parsed tree
	secStart := time.Now()
	resp.Decision = s.Security.AnalyzeAST(req.Query, ast, parseErr)
	resp.Metrics.SecurityTimeMS = ms(time.Since(secStart))
	if resp.Decision.Block {
		resp.Error = "Query blocked by security engine: " + resp.Decision.Reason
		finish()
		return
	}
	if parseErr != nil {
		resp.Error = fmt.Sprintf("Parse error: %v", parseErr)
		finish()
		return
	}

	readOnly := ast.Type == "SELECT" || ast.Type == "UNION"
	if readOnly {
		if cachedRows, hit := s.cache.Get(req.Query, nil); hit {
			resp.CacheHit = true
			resp.Results = cachedRows
			finish()
			return
		}
	}

	// 3. Planner
	planStart := time.Now()
	plan, err := planner.GeneratePlan(ast)
	resp.Metrics.PlanTimeMS = ms(time.Since(planStart))
	if err != nil {
		resp.Error = fmt.Sprintf("Plan error: %v", err)
		finish()
		return
	}
	resp.Plan = plan

	// 4. Execution
	execStart := time.Now()
	if s.Engine != nil {
		res, _, err := s.Engine.Query(r.Context(), req.Query)
		if err != nil {
			resp.Error = fmt.Sprintf("Execution error: %v", err)
			resp.Metrics.ExecTimeMS = ms(time.Since(execStart))
			finish()
			return
		}
		resp.Results, resp.Truncated, err = readRows(res, maxResultRows)
		if err != nil {
			resp.Error = fmt.Sprintf("Execution error: %v", err)
			resp.Results = nil
			resp.Metrics.ExecTimeMS = ms(time.Since(execStart))
			finish()
			return
		}
	} else {
		resp.Results = sampleRows(ast)
	}
	resp.Metrics.ExecTimeMS = ms(time.Since(execStart))

	if readOnly {
		if !resp.Truncated { // a cached copy could not report the truncation
			s.cache.Set(req.Query, nil, resp.Results, resultCacheTTL)
		}
	} else {
		s.cache.Invalidate() // a write may have changed cached results
	}
	finish()
}

// readRows materialises at most limit rows and closes res. It reports
// whether rows were left unread and any error raised while reading.
func readRows(res internal.Result, limit int) ([]federation.Row, bool, error) {
	defer res.Close()
	cols := res.Columns()
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	var rows []federation.Row
	for res.Next() {
		if len(rows) == limit {
			return rows, true, nil
		}
		if err := res.Scan(ptrs...); err != nil {
			return nil, false, err
		}
		row := make(federation.Row, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				row[c] = string(b)
			} else {
				row[c] = vals[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, false, res.Err()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func sampleRows(ast *parser.QueryAST) []federation.Row {
	if len(ast.Tables) == 0 {
		return nil
	}
	row1 := make(federation.Row)
	row2 := make(federation.Row)
	for _, t := range ast.Tables {
		prefix := ""
		if t.Alias != "" {
			prefix = t.Alias + "."
		}
		row1[prefix+"id"] = 1
		row2[prefix+"id"] = 2
		row1[prefix+"name"] = "Alice"
		row2[prefix+"name"] = "Bob"
	}
	return []federation.Row{row1, row2}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]map[string]int{}
	if s.Engine != nil {
		for name, db := range s.Engine.Sources {
			if t, ok := db.Conn().(interface{ PoolStats() sql.DBStats }); ok {
				st := t.PoolStats()
				stats[name] = map[string]int{"active": st.InUse, "idle": st.Idle, "max": st.MaxOpenConnections}
			}
		}
	} else {
		// Demo mode: illustrative values.
		stats = map[string]map[string]int{
			"postgres": {"active": 12, "idle": 8, "max": 20},
			"mysql":    {"active": 4, "idle": 16, "max": 20},
			"mongodb":  {"active": 1, "idle": 9, "max": 10},
		}
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleRouterDemo(w http.ResponseWriter, r *http.Request) {
	var req aiRouterDemoRequest
	if !decodePost(w, r, &req) {
		return
	}
	if len(req.Queries) > maxRouterProbes {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d queries per request", maxRouterProbes))
		return
	}

	resp := aiRouterDemoResponse{TrainedOn: len(router.SeedData), Predictions: []aiRouterPrediction{}}
	for _, q := range req.Queries {
		prediction := s.router.Predict(q)
		resp.Predictions = append(resp.Predictions, aiRouterPrediction{
			Query:      q,
			Database:   prediction.TargetDatabase,
			Dialect:    prediction.TargetDialect,
			Confidence: prediction.Confidence, // posterior probability
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

type tableInfo struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

// schemaQueries list user tables and their columns for each SQL backend.
var schemaQueries = map[string]string{
	"postgres": `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = current_schema() ORDER BY table_name, ordinal_position`,
	"mysql": `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = DATABASE() ORDER BY table_name, ordinal_position`,
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	if s.Engine == nil {
		writeJSON(w, http.StatusOK, demoSchema)
		return
	}
	out := map[string][]tableInfo{}
	for name, db := range s.Engine.Sources {
		q, ok := schemaQueries[db.Driver()]
		if !ok {
			continue
		}
		tables, err := listTables(r.Context(), db, q)
		if err != nil {
			log.Printf("unidb-web: reading schema of %s: %v", name, err)
			continue
		}
		out[name] = tables
	}
	writeJSON(w, http.StatusOK, out)
}

func listTables(ctx context.Context, db *api.DB, q string) ([]tableInfo, error) {
	res, err := db.Conn().Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	tables := []tableInfo{}
	for res.Next() {
		var table, col string
		if err := res.Scan(&table, &col); err != nil {
			return nil, err
		}
		if n := len(tables); n == 0 || tables[n-1].Name != table {
			tables = append(tables, tableInfo{Name: table})
		}
		t := &tables[len(tables)-1]
		t.Columns = append(t.Columns, col)
	}
	return tables, nil
}

var demoSchema = map[string][]tableInfo{
	"postgres": {
		{Name: "users", Columns: []string{"id", "name", "email", "created_at"}},
		{Name: "profiles", Columns: []string{"user_id", "bio", "avatar_url"}},
	},
	"mysql": {
		{Name: "orders", Columns: []string{"id", "user_id", "total", "status"}},
		{Name: "items", Columns: []string{"id", "order_id", "product_id", "quantity"}},
	},
	"mongodb": {
		{Name: "logs", Columns: []string{"_id", "level", "message", "timestamp"}},
		{Name: "sessions", Columns: []string{"_id", "user_id", "token", "expires"}},
	},
}

// EngineFromEnv builds a live engine from UNIDB_SOURCES, a comma-separated
// list of name=URI pairs such as
// "postgres=postgres://u:p@host:5432/db,mysql=mysql://u:p@host:3306/db".
// The first source is the default. It returns nil when the variable is unset.
func EngineFromEnv() (*engine.Engine, error) {
	spec := strings.TrimSpace(os.Getenv("UNIDB_SOURCES"))
	if spec == "" {
		return nil, nil
	}
	return BuildEngine(spec)
}

// BuildEngine connects to every source in spec (see EngineFromEnv).
func BuildEngine(spec string) (*engine.Engine, error) {
	e := &engine.Engine{Sources: map[string]*api.DB{}, Security: security.NewSecurityEngine()}
	for _, part := range strings.Split(spec, ",") {
		name, uri, ok := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || uri == "" {
			e.Close()
			return nil, fmt.Errorf("UNIDB_SOURCES: expected name=uri, got %q", part)
		}
		if _, dup := e.Sources[name]; dup {
			e.Close()
			return nil, fmt.Errorf("UNIDB_SOURCES: source %q listed twice", name)
		}
		db, err := api.Connect(uri)
		if err != nil {
			e.Close()
			return nil, fmt.Errorf("UNIDB_SOURCES %s: %w", name, err)
		}
		e.Sources[name] = db
		if e.Default == "" {
			e.Default = name
		}
	}
	return e, nil
}

// Run serves the dashboard on addr until ctx is cancelled, then shuts down
// gracefully.
func Run(ctx context.Context, addr string, e *engine.Engine) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           NewServer(e).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// StartServer serves the dashboard on the given port, using UNIDB_SOURCES
// for live mode. It blocks until the server fails.
func StartServer(port int) error {
	e, err := EngineFromEnv()
	if err != nil {
		return err
	}
	return Run(context.Background(), fmt.Sprintf(":%d", port), e)
}
