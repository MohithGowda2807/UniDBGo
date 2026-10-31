package security

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"vitess.io/vitess/go/vt/sqlparser"
)

// value is the result of statically evaluating a constant sub-expression.
type value struct {
	kind byte // 'n' number, 's' string, 'z' NULL
	num  float64
	str  string
}

func numVal(f float64) value { return value{kind: 'n', num: f} }
func strVal(s string) value  { return value{kind: 's', str: s} }
func boolVal(b bool) value {
	if b {
		return numVal(1)
	}
	return numVal(0)
}

var nullVal = value{kind: 'z'}

// asNumber follows MySQL's implicit conversion: a string becomes the number
// formed by its longest numeric prefix, or 0.
func (v value) asNumber() float64 {
	switch v.kind {
	case 'n':
		return v.num
	case 's':
		s := strings.TrimSpace(v.str)
		end := 0
		for end < len(s) && strings.IndexByte("+-.0123456789eE", s[end]) >= 0 {
			end++
		}
		for end > 0 {
			if f, err := strconv.ParseFloat(s[:end], 64); err == nil {
				return f
			}
			end--
		}
	}
	return 0
}

func (v value) asString() string {
	if v.kind == 's' {
		return v.str
	}
	return strconv.FormatFloat(v.num, 'f', -1, 64)
}

func (v value) truthy() bool { return v.kind != 'z' && v.asNumber() != 0 }

// eval implements the invariant function Φ. It returns ok=false ("Dynamic")
// when the value depends on column data or bind variables.
func eval(e sqlparser.Expr) (value, bool) {
	switch n := e.(type) {
	case *sqlparser.Literal:
		switch n.Type {
		case sqlparser.IntVal, sqlparser.FloatVal, sqlparser.DecimalVal:
			f, err := strconv.ParseFloat(n.Val, 64)
			return numVal(f), err == nil
		case sqlparser.StrVal, sqlparser.DateVal, sqlparser.TimeVal, sqlparser.TimestampVal:
			return strVal(n.Val), true
		case sqlparser.HexNum: // 0x41
			b, ok := decodeHex(strings.TrimPrefix(strings.ToLower(n.Val), "0x"))
			return strVal(b), ok
		case sqlparser.HexVal: // X'41'
			b, ok := decodeHex(n.Val)
			return strVal(b), ok
		case sqlparser.BitNum: // 0b101
			u, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(n.Val), "0b"), 2, 64)
			return numVal(float64(u)), err == nil
		}
		return value{}, false
	case *sqlparser.NullVal:
		return nullVal, true
	case sqlparser.BoolVal:
		return boolVal(bool(n)), true
	case *sqlparser.IntroducerExpr: // _utf8mb4'x'
		return eval(n.Expr)
	case *sqlparser.CollateExpr:
		return eval(n.Expr)
	case *sqlparser.NotExpr:
		v, ok := eval(n.Expr)
		if !ok || v.kind == 'z' {
			return v, ok
		}
		return boolVal(!v.truthy()), true
	case *sqlparser.AndExpr:
		l, lok := eval(n.Left)
		r, rok := eval(n.Right)
		if (lok && !l.truthy() && l.kind != 'z') || (rok && !r.truthy() && r.kind != 'z') {
			return boolVal(false), true
		}
		if lok && rok {
			return boolVal(l.truthy() && r.truthy()), true
		}
		return value{}, false
	case *sqlparser.OrExpr:
		l, lok := eval(n.Left)
		r, rok := eval(n.Right)
		if (lok && l.truthy()) || (rok && r.truthy()) {
			return boolVal(true), true
		}
		if lok && rok {
			return boolVal(false), true
		}
		return value{}, false
	case *sqlparser.XorExpr:
		l, lok := eval(n.Left)
		r, rok := eval(n.Right)
		if !lok || !rok {
			return value{}, false
		}
		if l.kind == 'z' || r.kind == 'z' {
			return nullVal, true
		}
		return boolVal(l.truthy() != r.truthy()), true
	case *sqlparser.UnaryExpr:
		v, ok := eval(n.Expr)
		if !ok || v.kind == 'z' {
			return v, ok
		}
		switch n.Operator {
		case sqlparser.UMinusOp:
			return numVal(-v.asNumber()), true
		case sqlparser.UPlusOp:
			return numVal(v.asNumber()), true
		case sqlparser.BangOp:
			return boolVal(!v.truthy()), true
		case sqlparser.TildaOp:
			return numVal(float64(^uint64(v.asNumber()))), true
		}
		return v, true
	case *sqlparser.BinaryExpr:
		l, lok := eval(n.Left)
		r, rok := eval(n.Right)
		if !lok || !rok {
			return value{}, false
		}
		if l.kind == 'z' || r.kind == 'z' {
			return nullVal, true
		}
		a, b := l.asNumber(), r.asNumber()
		switch n.Operator {
		case sqlparser.PlusOp:
			return numVal(a + b), true
		case sqlparser.MinusOp:
			return numVal(a - b), true
		case sqlparser.MultOp:
			return numVal(a * b), true
		case sqlparser.DivOp:
			if b == 0 {
				return nullVal, true
			}
			return numVal(a / b), true
		case sqlparser.IntDivOp:
			if b == 0 {
				return nullVal, true
			}
			return numVal(math.Trunc(a / b)), true
		case sqlparser.ModOp:
			if b == 0 {
				return nullVal, true
			}
			return numVal(math.Mod(a, b)), true
		case sqlparser.BitAndOp:
			return numVal(float64(uint64(a) & uint64(b))), true
		case sqlparser.BitOrOp:
			return numVal(float64(uint64(a) | uint64(b))), true
		case sqlparser.BitXorOp:
			return numVal(float64(uint64(a) ^ uint64(b))), true
		case sqlparser.ShiftLeftOp:
			return numVal(float64(uint64(a) << uint64(b))), true
		case sqlparser.ShiftRightOp:
			return numVal(float64(uint64(a) >> uint64(b))), true
		}
		return value{}, false
	case *sqlparser.ComparisonExpr:
		return evalComparison(n)
	case *sqlparser.BetweenExpr:
		v, ok1 := eval(n.Left)
		lo, ok2 := eval(n.From)
		hi, ok3 := eval(n.To)
		if !ok1 || !ok2 || !ok3 {
			return value{}, false
		}
		in := compare(v, lo) >= 0 && compare(v, hi) <= 0
		if !n.IsBetween {
			in = !in
		}
		return boolVal(in), true
	case *sqlparser.IsExpr:
		v, ok := eval(n.Left)
		if !ok {
			return value{}, false
		}
		switch n.Right {
		case sqlparser.IsNullOp:
			return boolVal(v.kind == 'z'), true
		case sqlparser.IsNotNullOp:
			return boolVal(v.kind != 'z'), true
		case sqlparser.IsTrueOp:
			return boolVal(v.truthy()), true
		case sqlparser.IsNotTrueOp:
			return boolVal(!v.truthy()), true
		case sqlparser.IsFalseOp:
			return boolVal(v.kind != 'z' && !v.truthy()), true
		case sqlparser.IsNotFalseOp:
			return boolVal(v.kind == 'z' || v.truthy()), true
		}
	case *sqlparser.FuncExpr:
		return evalFunc(n.Name.Lowered(), n.Exprs)
	case *sqlparser.CharExpr:
		return evalFunc("char", n.Exprs)
	case *sqlparser.CaseExpr:
		return evalCase(n)
	case *sqlparser.CastExpr:
		return evalCast(n.Expr, n.Type)
	case *sqlparser.ConvertExpr:
		return evalCast(n.Expr, n.Type)
	}
	return value{}, false
}

// evalCast evaluates CAST(e AS type) / CONVERT(e, type).
func evalCast(e sqlparser.Expr, t *sqlparser.ConvertType) (value, bool) {
	v, ok := eval(e)
	if !ok || v.kind == 'z' || t == nil {
		return v, ok
	}
	switch strings.ToLower(t.Type) {
	case "signed", "unsigned", "integer", "int", "signed integer", "unsigned integer":
		return numVal(math.Trunc(v.asNumber())), true
	case "decimal", "double", "float", "real", "numeric":
		return numVal(v.asNumber()), true
	case "char", "nchar", "binary", "text", "varchar":
		return strVal(v.asString()), true
	}
	return value{}, false
}

// evalCase evaluates CASE [x] WHEN ... THEN ... [ELSE ...] END.
func evalCase(n *sqlparser.CaseExpr) (value, bool) {
	var subject value
	if n.Expr != nil {
		var ok bool
		if subject, ok = eval(n.Expr); !ok {
			return value{}, false
		}
	}
	for _, w := range n.Whens {
		c, ok := eval(w.Cond)
		if !ok {
			return value{}, false
		}
		hit := c.truthy()
		if n.Expr != nil {
			hit = subject.kind != 'z' && c.kind != 'z' && compare(subject, c) == 0
		}
		if hit {
			return eval(w.Val)
		}
	}
	if n.Else == nil {
		return nullVal, true
	}
	return eval(n.Else)
}

func evalComparison(n *sqlparser.ComparisonExpr) (value, bool) {
	l, lok := eval(n.Left)
	if n.Operator == sqlparser.InOp || n.Operator == sqlparser.NotInOp {
		tuple, isTuple := n.Right.(sqlparser.ValTuple)
		if !lok || !isTuple {
			return value{}, false
		}
		found := false
		for _, item := range tuple {
			v, ok := eval(item)
			if !ok {
				return value{}, false
			}
			if v.kind != 'z' && l.kind != 'z' && compare(l, v) == 0 {
				found = true
			}
		}
		if n.Operator == sqlparser.NotInOp {
			found = !found
		}
		return boolVal(found), true
	}
	r, rok := eval(n.Right)
	if !lok || !rok {
		return value{}, false
	}
	if n.Operator == sqlparser.NullSafeEqualOp {
		if l.kind == 'z' || r.kind == 'z' {
			return boolVal(l.kind == r.kind), true
		}
		return boolVal(compare(l, r) == 0), true
	}
	if l.kind == 'z' || r.kind == 'z' {
		return nullVal, true
	}
	c := compare(l, r)
	switch n.Operator {
	case sqlparser.EqualOp:
		return boolVal(c == 0), true
	case sqlparser.NotEqualOp:
		return boolVal(c != 0), true
	case sqlparser.LessThanOp:
		return boolVal(c < 0), true
	case sqlparser.LessEqualOp:
		return boolVal(c <= 0), true
	case sqlparser.GreaterThanOp:
		return boolVal(c > 0), true
	case sqlparser.GreaterEqualOp:
		return boolVal(c >= 0), true
	case sqlparser.LikeOp, sqlparser.NotLikeOp:
		m := likeMatch(l.asString(), r.asString())
		if n.Operator == sqlparser.NotLikeOp {
			m = !m
		}
		return boolVal(m), true
	case sqlparser.RegexpOp, sqlparser.NotRegexpOp:
		re, err := regexp.Compile("(?i)" + r.asString())
		if err != nil {
			return value{}, false
		}
		m := re.MatchString(l.asString())
		if n.Operator == sqlparser.NotRegexpOp {
			m = !m
		}
		return boolVal(m), true
	}
	return value{}, false
}

// compare uses string comparison (case-insensitive, as with MySQL's default
// collation) when both sides are strings, and numeric comparison otherwise.
func compare(a, b value) int {
	if a.kind == 's' && b.kind == 's' {
		return strings.Compare(strings.ToLower(a.str), strings.ToLower(b.str))
	}
	x, y := a.asNumber(), b.asNumber()
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

func evalFunc(name string, exprs []sqlparser.Expr) (value, bool) {
	var args []value
	for _, ae := range exprs {
		v, ok := eval(ae)
		if !ok {
			return value{}, false
		}
		args = append(args, v)
	}
	switch name {
	case "coalesce", "ifnull":
		for _, a := range args {
			if a.kind != 'z' {
				return a, true
			}
		}
		return nullVal, true
	case "nullif":
		if len(args) == 2 {
			if args[0].kind != 'z' && args[1].kind != 'z' && compare(args[0], args[1]) == 0 {
				return nullVal, true
			}
			return args[0], true
		}
	case "if":
		if len(args) == 3 {
			if args[0].truthy() {
				return args[1], true
			}
			return args[2], true
		}
	case "char", "chr":
		var b strings.Builder
		for _, a := range args {
			b.WriteByte(byte(int(a.asNumber())))
		}
		return strVal(b.String()), true
	case "concat":
		var b strings.Builder
		for _, a := range args {
			if a.kind == 'z' {
				return nullVal, true
			}
			b.WriteString(a.asString())
		}
		return strVal(b.String()), true
	case "lower", "lcase":
		if len(args) == 1 {
			return strVal(strings.ToLower(args[0].asString())), true
		}
	case "upper", "ucase":
		if len(args) == 1 {
			return strVal(strings.ToUpper(args[0].asString())), true
		}
	case "ascii", "ord":
		if len(args) == 1 && args[0].asString() != "" {
			return numVal(float64(args[0].asString()[0])), true
		}
	case "abs":
		if len(args) == 1 {
			return numVal(math.Abs(args[0].asNumber())), true
		}
	}
	return value{}, false
}

func decodeHex(s string) (string, bool) {
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return "", false
		}
		b = append(b, byte(v))
	}
	return string(b), true
}

// likeMatch implements SQL LIKE with % and _ wildcards, case-insensitively.
func likeMatch(s, pattern string) bool {
	var re strings.Builder
	re.WriteString("(?is)^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		case '\\':
			if i+1 < len(pattern) {
				i++
				re.WriteString(regexp.QuoteMeta(string(pattern[i])))
			}
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	m, err := regexp.MatchString(re.String(), s)
	return err == nil && m
}
