package security

import (
	"encoding/json"
	"strings"
)

// CatServerCode marks a command document that asks the server to execute
// JavaScript, the usual vehicle of NoSQL injection.
const CatServerCode Category = "server-side-code"

// serverCodeOperators run caller-supplied JavaScript on a MongoDB server.
var serverCodeOperators = map[string]bool{
	"$where":       true,
	"$function":    true,
	"$accumulator": true,
	"mapreduce":    true,
	"$eval":        true,
}

// IsDocument reports whether query is a JSON command document (for example a
// MongoDB command such as {"find": "users", "filter": {...}}) rather than SQL.
func IsDocument(query string) bool {
	t := strings.TrimSpace(query)
	return strings.HasPrefix(t, "{") && json.Valid([]byte(t))
}

// AnalyzeDocument inspects a JSON command document. SQL invariants do not
// apply to documents; instead the document is decoded and rejected if any key,
// at any depth, invokes server-side JavaScript ($where, $function,
// $accumulator, mapReduce, $eval). Documents that are not valid JSON are rejected.
func (e *SecurityEngine) AnalyzeDocument(doc string) Decision {
	if !json.Valid([]byte(doc)) {
		return block(CatUnparseable, "invalid command document")
	}
	if op := findServerCode(doc); op != "" {
		return block(CatServerCode, "command document uses %s, which executes JavaScript on the server", op)
	}
	return Decision{}
}

// findServerCode streams the document's tokens, so that every key is seen,
// including keys repeated within one object: a map would keep only the last
// of them, while the MongoDB driver forwards all of them.
func findServerCode(doc string) string {
	dec := json.NewDecoder(strings.NewReader(doc))
	type frame struct{ object, expectKey bool }
	var stack []frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		top := len(stack) - 1
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if top >= 0 && stack[top].object {
					stack[top].expectKey = true // the nested value completes a member
				}
				stack = append(stack, frame{object: t == '{', expectKey: t == '{'})
			default:
				stack = stack[:top]
			}
		case string:
			if top >= 0 && stack[top].object {
				if stack[top].expectKey {
					if serverCodeOperators[strings.ToLower(t)] {
						return t
					}
					stack[top].expectKey = false
				} else {
					stack[top].expectKey = true
				}
			}
		default:
			if top >= 0 && stack[top].object {
				stack[top].expectKey = true
			}
		}
	}
}
