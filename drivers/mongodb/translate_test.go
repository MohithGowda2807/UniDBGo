package mongodb

import (
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestTranslate(t *testing.T) {
	spec, err := Translate("SELECT name, age FROM users WHERE age > 25 AND country IN ('IN', 'US') AND name LIKE 'a%' ORDER BY age DESC LIMIT 10 OFFSET 20", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := bson.MarshalExtJSON(bson.D{{Key: "f", Value: spec.Filter}}, false, false)
	want := `{"f":{"age":{"$gt":25},"country":{"$in":["IN","US"]},"name":{"$regex":"^a.*$","$options":"i"}}}`
	if string(got) != want {
		t.Errorf("filter\n got %s\nwant %s", got, want)
	}
	if spec.Collection != "users" || spec.Limit != 10 || spec.Skip != 20 || len(spec.Columns) != 2 {
		t.Errorf("unexpected spec %+v", spec)
	}
	if spec.Sort[0].Key != "age" || spec.Sort[0].Value != -1 {
		t.Errorf("unexpected sort %v", spec.Sort)
	}
}

func TestTranslateBindsArgs(t *testing.T) {
	spec, err := Translate("SELECT * FROM users WHERE id = ? AND active = ?", []any{7, true})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Filter[0].Value != 7 || spec.Filter[1].Value != true {
		t.Errorf("args not bound: %v", spec.Filter)
	}
}

func TestTranslateRejectsOutsideSubset(t *testing.T) {
	for _, q := range []string{
		"SELECT * FROM a JOIN b ON a.id = b.id",
		"SELECT * FROM a WHERE x = 1 OR y = 2",
		"SELECT COUNT(*) FROM a GROUP BY x",
		"DELETE FROM a",
	} {
		if _, err := Translate(q, nil); !errors.Is(err, ErrUntranslatable) {
			t.Errorf("%q: expected ErrUntranslatable, got %v", q, err)
		}
	}
}

func TestTranslateReviewCases(t *testing.T) {
	spec, err := Translate("SELECT * FROM t WHERE a = $2 AND b = $1", []any{"B", "A"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Filter[0].Value != "A" || spec.Filter[1].Value != "B" {
		t.Errorf("placeholders bound out of order: %v", spec.Filter)
	}

	spec, _ = Translate("SELECT * FROM t LIMIT 0", nil)
	if !spec.HasLimit || spec.Limit != 0 {
		t.Errorf("LIMIT 0 lost: %+v", spec)
	}

	spec, _ = Translate("SELECT * FROM t WHERE a <> 1 AND b NOT IN (2, 3)", nil)
	got, _ := bson.MarshalExtJSON(bson.D{{Key: "f", Value: spec.Filter}}, false, false)
	if want := `{"f":{"a":{"$nin":[1,null]},"b":{"$nin":[2,3,null]}}}`; string(got) != want {
		t.Errorf("NULL semantics\n got %s\nwant %s", got, want)
	}

	if re := likeToRegex(`100\%`); re != `^100%$` {
		t.Errorf("LIKE escape: %s", re)
	}
	if re := likeToRegex(`a_b%`); re != `^a.b.*$` {
		t.Errorf("LIKE wildcards: %s", re)
	}
}
