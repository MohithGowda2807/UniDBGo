package router

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Dheeran-git/UniDBGo/planner"
)

func TestAIRouter(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test_db.json")
	defer os.Remove(tmpFile)

	err := InitAIRouter(tmpFile)
	if err != nil {
		t.Fatalf("Failed to init AIRouter: %v", err)
	}

	ar, ok := ActiveRouter.(*AIRouter)
	if !ok {
		t.Fatal("ActiveRouter is not of type *AIRouter")
	}
	ar.Threshold = 0.5

	plan := &planner.ExecutionPlan{
		Steps: []planner.ExecutionStep{
			{ID: 1, Type: "SCAN", Query: "SELECT payload->>'name' FROM events WHERE id = $1"},
			{ID: 2, Type: "SCAN", Query: "SELECT JSON_EXTRACT(data, '$.name') FROM configs"},
			{ID: 3, Type: "SCAN", Query: `{ "find": "users", "filter": { "age": { "$gt": 25 } } }`},
			{ID: 4, Type: "SCAN", Database: "mysql", Query: "SELECT 1"},
		},
	}

	routes, err := ar.Route(plan)
	if err != nil {
		t.Fatalf("Failed to route: %v", err)
	}

	if len(routes) != 4 {
		t.Fatalf("Expected 4 routes, got %d", len(routes))
	}

	want := []string{"postgres", "mysql", "mongodb", "mysql"}
	for i, w := range want {
		if routes[i].Database != w {
			t.Errorf("route %d: expected %s, got %s (confidence %.3f)", i+1, w, routes[i].Database, routes[i].Confidence)
		}
	}
}

func TestPosteriorIsProbability(t *testing.T) {
	m := NewRoutingModel()
	m.Train(SeedData)
	for _, q := range []string{"SELECT 1", "SELECT * FROM t WHERE id = $1", "{}"} {
		p := m.Predict(q)
		if p.Confidence <= 0 || p.Confidence > 1 {
			t.Errorf("%q: posterior %v outside (0,1]", q, p.Confidence)
		}
	}
}

func TestThresholdFallsBack(t *testing.T) {
	m := NewRoutingModel()
	m.Train(SeedData)
	ar := NewAIRouterWithModel(m, nil)
	ar.Threshold = 1.01 // nothing is confident enough
	routes, _ := ar.Route(&planner.ExecutionPlan{Steps: []planner.ExecutionStep{{ID: 1, Type: "SCAN", Query: "SELECT 1"}}})
	if routes[0].Database != "default" {
		t.Errorf("expected fallback, got %s", routes[0].Database)
	}
}

func TestCorruptTrainingStoreIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAIRouter(path); err == nil {
		t.Fatal("a corrupt training store was silently ignored")
	}
}
