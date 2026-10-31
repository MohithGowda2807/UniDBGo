package mongodb

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Dheeran-git/UniDBGo/parser"
	"go.mongodb.org/mongo-driver/v2/bson"
	"vitess.io/vitess/go/vt/sqlparser"
)

var ErrUntranslatable = errors.New("mongodb: query outside the translatable SQL subset")

// FindSpec is a find command derived from a SQL SELECT.
type FindSpec struct {
	Collection string
	Filter     bson.D
	Projection bson.D
	Sort       bson.D
	Limit      int64
	Skip       int64
	// HasLimit is true when the query had a LIMIT clause; LIMIT 0 then
	// means "no rows", whereas MongoDB treats a zero limit as unlimited.
	HasLimit bool
	Columns  []string // projected columns, nil for SELECT *
}

// Translate converts the supported SQL subset into a find command:
//
//	SELECT <cols | *> FROM <collection>
//	[WHERE <col op value> [AND ...]]   op ∈ =, !=, <>, <, <=, >, >=, IN, NOT IN, LIKE, IS [NOT] NULL
//	[ORDER BY <col> [ASC|DESC], ...] [LIMIT n [OFFSET m]]
//
// Joins, OR, GROUP BY and expressions in the select list are rejected.
// Bind variables are taken from args by position: $n and :vn select the
// n-th argument, and ? placeholders are numbered in order of appearance.
func Translate(query string, args []any) (*FindSpec, error) {
	stmts, err := parser.Statements(query)
	if err != nil || len(stmts) != 1 {
		return nil, fmt.Errorf("%w: %v", ErrUntranslatable, err)
	}
	stmt := stmts[0]
	sel, ok := stmt.(*sqlparser.Select)
	if !ok || len(sel.From) != 1 || sel.GroupBy != nil || sel.Having != nil || sel.Distinct {
		return nil, fmt.Errorf("%w: only single-collection SELECT is supported", ErrUntranslatable)
	}
	at, ok := sel.From[0].(*sqlparser.AliasedTableExpr)
	if !ok {
		return nil, fmt.Errorf("%w: joins are not supported", ErrUntranslatable)
	}
	name, ok := at.Expr.(sqlparser.TableName)
	if !ok {
		return nil, fmt.Errorf("%w: sub-queries are not supported", ErrUntranslatable)
	}

	b := &binder{args: args}
	spec := &FindSpec{Collection: name.Name.String(), Filter: bson.D{}}

	for _, se := range sel.GetColumns() {
		switch e := se.(type) {
		case *sqlparser.StarExpr:
			spec.Columns, spec.Projection = nil, nil
		case *sqlparser.AliasedExpr:
			col, ok := e.Expr.(*sqlparser.ColName)
			if !ok {
				return nil, fmt.Errorf("%w: select list must contain plain columns", ErrUntranslatable)
			}
			spec.Columns = append(spec.Columns, col.Name.String())
			spec.Projection = append(spec.Projection, bson.E{Key: col.Name.String(), Value: 1})
		}
	}

	if sel.Where != nil {
		if err := b.conjunction(sel.Where.Expr, &spec.Filter); err != nil {
			return nil, err
		}
	}

	for _, o := range sel.OrderBy {
		col, ok := o.Expr.(*sqlparser.ColName)
		if !ok {
			return nil, fmt.Errorf("%w: ORDER BY must name a column", ErrUntranslatable)
		}
		dir := 1
		if o.Direction == sqlparser.DescOrder {
			dir = -1
		}
		spec.Sort = append(spec.Sort, bson.E{Key: col.Name.String(), Value: dir})
	}

	if sel.Limit != nil {
		spec.HasLimit = true
		if spec.Limit, err = b.int(sel.Limit.Rowcount); err != nil {
			return nil, err
		}
		if sel.Limit.Offset != nil {
			if spec.Skip, err = b.int(sel.Limit.Offset); err != nil {
				return nil, err
			}
		}
	}
	return spec, nil
}

type binder struct {
	args []any
}

func (b *binder) conjunction(e sqlparser.Expr, out *bson.D) error {
	switch n := e.(type) {
	case *sqlparser.AndExpr:
		if err := b.conjunction(n.Left, out); err != nil {
			return err
		}
		return b.conjunction(n.Right, out)
	case *sqlparser.ComparisonExpr:
		col, ok := n.Left.(*sqlparser.ColName)
		if !ok {
			return fmt.Errorf("%w: comparison must have a column on the left", ErrUntranslatable)
		}
		var cond any
		switch n.Operator {
		case sqlparser.InOp, sqlparser.NotInOp:
			tuple, ok := n.Right.(sqlparser.ValTuple)
			if !ok {
				return fmt.Errorf("%w: IN requires a value list", ErrUntranslatable)
			}
			vals := bson.A{}
			for _, item := range tuple {
				v, err := b.value(item)
				if err != nil {
					return err
				}
				vals = append(vals, v)
			}
			if n.Operator == sqlparser.NotInOp {
				// SQL NOT IN never matches NULL; $nin alone would match
				// missing and null fields.
				cond = bson.D{{Key: "$nin", Value: append(vals, nil)}}
			} else {
				cond = bson.D{{Key: "$in", Value: vals}}
			}
		default:
			v, err := b.value(n.Right)
			if err != nil {
				return err
			}
			switch n.Operator {
			case sqlparser.EqualOp:
				cond = v
			case sqlparser.NotEqualOp:
				// SQL <> never matches NULL; exclude missing and null fields.
				cond = bson.D{{Key: "$nin", Value: bson.A{v, nil}}}
			case sqlparser.LessThanOp:
				cond = bson.D{{Key: "$lt", Value: v}}
			case sqlparser.LessEqualOp:
				cond = bson.D{{Key: "$lte", Value: v}}
			case sqlparser.GreaterThanOp:
				cond = bson.D{{Key: "$gt", Value: v}}
			case sqlparser.GreaterEqualOp:
				cond = bson.D{{Key: "$gte", Value: v}}
			case sqlparser.LikeOp:
				s, ok := v.(string)
				if !ok {
					return fmt.Errorf("%w: LIKE needs a string pattern", ErrUntranslatable)
				}
				cond = bson.D{{Key: "$regex", Value: likeToRegex(s)}, {Key: "$options", Value: "i"}}
			default:
				return fmt.Errorf("%w: operator %s", ErrUntranslatable, n.Operator.ToString())
			}
		}
		*out = append(*out, bson.E{Key: col.Name.String(), Value: cond})
		return nil
	case *sqlparser.IsExpr:
		col, ok := n.Left.(*sqlparser.ColName)
		if !ok {
			return fmt.Errorf("%w: IS must test a column", ErrUntranslatable)
		}
		switch n.Right {
		case sqlparser.IsNullOp:
			*out = append(*out, bson.E{Key: col.Name.String(), Value: nil})
		case sqlparser.IsNotNullOp:
			*out = append(*out, bson.E{Key: col.Name.String(), Value: bson.D{{Key: "$ne", Value: nil}}})
		default:
			return fmt.Errorf("%w: operator %s", ErrUntranslatable, n.Right.ToString())
		}
		return nil
	}
	return fmt.Errorf("%w: only conjunctions of comparisons are supported", ErrUntranslatable)
}

func (b *binder) value(e sqlparser.Expr) (any, error) {
	switch n := e.(type) {
	case *sqlparser.Literal:
		switch n.Type {
		case sqlparser.StrVal:
			return n.Val, nil
		case sqlparser.IntVal:
			return strconv.ParseInt(n.Val, 10, 64)
		case sqlparser.FloatVal, sqlparser.DecimalVal:
			return strconv.ParseFloat(n.Val, 64)
		}
	case *sqlparser.Argument:
		// The parser names ? placeholders :v1, :v2, ... and $n becomes :pn.
		name := n.Name
		if len(name) < 2 || (name[0] != 'v' && name[0] != 'p') {
			return nil, fmt.Errorf("%w: unsupported placeholder :%s", ErrUntranslatable, name)
		}
		idx, err := strconv.Atoi(name[1:])
		if err != nil || idx < 1 {
			return nil, fmt.Errorf("%w: unsupported placeholder :%s", ErrUntranslatable, name)
		}
		if idx > len(b.args) {
			return nil, fmt.Errorf("mongodb: missing argument for :%s", name)
		}
		return b.args[idx-1], nil
	case *sqlparser.NullVal:
		return nil, nil
	case sqlparser.BoolVal:
		return bool(n), nil
	case *sqlparser.UnaryExpr:
		if n.Operator == sqlparser.UMinusOp {
			v, err := b.value(n.Expr)
			switch x := v.(type) {
			case int64:
				return -x, err
			case float64:
				return -x, err
			}
		}
	}
	return nil, fmt.Errorf("%w: unsupported value %s", ErrUntranslatable, sqlparser.String(e))
}

func (b *binder) int(e sqlparser.Expr) (int64, error) {
	v, err := b.value(e)
	if err != nil {
		return 0, err
	}
	switch x := v.(type) {
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	}
	return 0, fmt.Errorf("%w: LIMIT/OFFSET must be integers", ErrUntranslatable)
}

// likeToRegex converts a LIKE pattern; a backslash escapes %, _ or itself.
func likeToRegex(p string) string {
	var re strings.Builder
	re.WriteString("^")
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		case '\\':
			if i+1 < len(rs) {
				i++
				re.WriteString(regexp.QuoteMeta(string(rs[i])))
			} else {
				re.WriteString(regexp.QuoteMeta(`\`))
			}
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re.WriteString("$")
	return re.String()
}
