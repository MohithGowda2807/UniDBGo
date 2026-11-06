package security

import "testing"

func TestAnalyzeDocument(t *testing.T) {
	e := NewSecurityEngine()
	cases := []struct {
		doc   string
		block bool
	}{
		{`{"find": "users", "filter": {"age": {"$gt": 25}}}`, false},
		{`{"aggregate": "orders", "pipeline": [{"$match": {"status": "paid"}}], "cursor": {}}`, false},
		{`{"find": "users", "filter": {"$where": "this.a == 1"}}`, true},
		{`{"aggregate": "u", "pipeline": [{"$group": {"_id": 1, "x": {"$accumulator": {}}}}]}`, true},
		{`{"find": "u", "filter": {"$expr": {"$function": {"body": "f", "args": [], "lang": "js"}}}}`, true},
		{`{"mapReduce": "u", "map": "function(){}", "reduce": "function(){}"}`, true},
		{`{"find": "users", "filter": {"note": "$where is just text"}}`, false},
		{`{"find": `, true},
		{`{"find": "u", "filter": {"$expr": {"$function": {"body": "f"}}, "$expr": {"$eq": [1, 1]}}}`, true},
		{`{"find": "u", "filter": {"a": [1, {"b": "$where"}], "c": {"$where": "x"}}}`, true},
		{`{"find": "u", "filter": {"a": [{"x": 1}, {"y": "$function"}]}}`, false},
	}
	for _, c := range cases {
		if got := e.AnalyzeDocument(c.doc).Block; got != c.block {
			t.Errorf("%s: block=%v, want %v", c.doc, got, c.block)
		}
	}
	if !IsDocument(` {"find":"u"}`) || IsDocument("SELECT 1") || IsDocument("{not json") {
		t.Error("IsDocument")
	}
}
