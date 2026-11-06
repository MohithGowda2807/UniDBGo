package parser

import "testing"

func TestPostgresCommentRules(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT 1 --x\nFROM t", "SELECT 1 -- x\nFROM t"},
		{"SELECT 1 /* a /* b */ c */ FROM t", "SELECT 1 /*  a / * b * / c  */ FROM t"},
	}
	for _, c := range cases {
		if got := Normalize(c.in, Postgres); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, q := range []string{"SELECT 1 --x", "SELECT /* a /* b */ c */ 1"} {
		if !DialectSensitive(q) {
			t.Errorf("%q should be dialect-sensitive", q)
		}
	}
	if DialectSensitive("SELECT 1 -- comment\n") || DialectSensitive("SELECT /* c */ 1") || DialectSensitive("SELECT 5-3") {
		t.Error("ordinary comments and minus are not dialect-sensitive")
	}
}
