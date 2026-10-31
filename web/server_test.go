package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func post(t *testing.T, h http.Handler, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestQueryDemoMode(t *testing.T) {
	h := NewServer(nil).Handler()
	rec, out := post(t, h, "/api/query", `{"query":"SELECT u.name FROM postgres.users u JOIN mysql.orders o ON u.id = o.user_id"}`)
	if rec.Code != http.StatusOK || out["mode"] != "demo" || out["error"] != nil {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if steps := out["plan"].(map[string]any)["Steps"].([]any); len(steps) != 3 {
		t.Fatalf("expected a federated plan, got %v", steps)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
}

func TestQueryBlocked(t *testing.T) {
	h := NewServer(nil).Handler()
	_, out := post(t, h, "/api/query", `{"query":"SELECT * FROM users WHERE id = 1 OR 0x61=0x61"}`)
	dec := out["decision"].(map[string]any)
	if dec["Block"] != true || dec["Category"] != "tautology" {
		t.Fatalf("expected a tautology block, got %v", dec)
	}
	if out["results"] != nil {
		t.Fatal("blocked query returned rows")
	}
}

func TestQueryRejectsBadRequests(t *testing.T) {
	h := NewServer(nil).Handler()
	cases := []struct {
		method, body string
		want         int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, "{not json", http.StatusBadRequest},
		{http.MethodPost, `{"query":"   "}`, http.StatusBadRequest},
		{http.MethodPost, `{"query":"` + strings.Repeat("x", maxBodyBytes) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, "/api/query", strings.NewReader(c.body)))
		if rec.Code != c.want {
			t.Errorf("%s %.20q: status %d, want %d", c.method, c.body, rec.Code, c.want)
		}
	}
}

func TestRouterDemo(t *testing.T) {
	h := NewServer(nil).Handler()
	rec, out := post(t, h, "/api/demo/ai-router", `{"queries":["SELECT * FROM users WHERE id = $1","SELECT * FROM `+"`users`"+` WHERE id = ?","{\"find\": \"users\"}"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	want := []string{"postgres", "mysql", "mongodb"}
	for i, p := range out["predictions"].([]any) {
		if got := p.(map[string]any)["database"]; got != want[i] {
			t.Errorf("prediction %d: %v, want %s", i, got, want[i])
		}
	}
	rec, _ = post(t, h, "/api/demo/ai-router", `{"queries":[`+strings.Repeat(`"x",`, maxRouterProbes)+`"x"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized router request: status %d", rec.Code)
	}
}

func TestStaticAssetsEmbedded(t *testing.T) {
	h := NewServer(nil).Handler()
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Errorf("GET %s: status %d, %d bytes", path, rec.Code, rec.Body.Len())
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s: missing security headers", path)
		}
	}
}

func TestBuildEngineRejectsBadSpec(t *testing.T) {
	for _, spec := range []string{"postgres", "=postgres://x", "a=mysql://u:p@h:1/d,a=mysql://u:p@h:1/d"} {
		if _, err := BuildEngine(spec); err == nil {
			t.Errorf("%q: expected an error", spec)
		}
	}
}
