package planner

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Dheeran-git/UniDBGo/parser"
	"vitess.io/vitess/go/vt/sqlparser"
)

var ErrUnsupportedFederation = errors.New("unsupported federated query")

// planFederatedQuery decomposes a two-table equi-join whose tables live in
// different databases into two SCAN steps and one JOIN step. Conjuncts of the
// WHERE clause that reference a single table are pushed into that table's
// SCAN query; the join itself is executed in memory by the federation engine.
func planFederatedQuery(ast *parser.QueryAST, meta QueryMetadata) (*ExecutionPlan, error) {
	sel, ok := ast.Stmt.(*sqlparser.Select)
	if !ok || len(sel.From) != 1 {
		return nil, fmt.Errorf("%w: expected a single SELECT ... JOIN", ErrUnsupportedFederation)
	}
	join, ok := sel.From[0].(*sqlparser.JoinTableExpr)
	if !ok || (join.Join != sqlparser.NormalJoinType && join.Join != sqlparser.StraightJoinType) || join.Condition == nil {
		return nil, fmt.Errorf("%w: only inner joins of two tables are supported", ErrUnsupportedFederation)
	}
	if sel.GroupBy != nil || sel.Having != nil || sel.OrderBy != nil || sel.Limit != nil {
		return nil, fmt.Errorf("%w: GROUP BY, HAVING, ORDER BY and LIMIT are not federated yet", ErrUnsupportedFederation)
	}

	left, lerr := scanSource(join.LeftExpr, ast.RawQuery)
	right, rerr := scanSource(join.RightExpr, ast.RawQuery)
	if lerr != nil || rerr != nil {
		return nil, fmt.Errorf("%w: join operands must be base tables", ErrUnsupportedFederation)
	}

	on, ok := join.Condition.On.(*sqlparser.ComparisonExpr)
	if !ok || on.Operator != sqlparser.EqualOp {
		return nil, fmt.Errorf("%w: join condition must be a single equality", ErrUnsupportedFederation)
	}
	lcol, lok := on.Left.(*sqlparser.ColName)
	rcol, rok := on.Right.(*sqlparser.ColName)
	if !lok || !rok {
		return nil, fmt.Errorf("%w: join condition must compare two columns", ErrUnsupportedFederation)
	}
	if lcol.Qualifier.Name.String() == right.alias {
		lcol, rcol = rcol, lcol
	}
	if lcol.Qualifier.Name.String() != left.alias || rcol.Qualifier.Name.String() != right.alias {
		return nil, fmt.Errorf("%w: join columns must be qualified by the table aliases", ErrUnsupportedFederation)
	}

	// Push single-table conjuncts down to the owning source.
	if sel.Where != nil {
		for _, c := range conjuncts(sel.Where.Expr) {
			owner := ownerOf(c)
			switch owner {
			case left.alias:
				left.filters = append(left.filters, unqualified(c, ast.RawQuery))
			case right.alias:
				right.filters = append(right.filters, unqualified(c, ast.RawQuery))
			default:
				return nil, fmt.Errorf("%w: predicate %q spans both tables", ErrUnsupportedFederation, sqlparser.String(c))
			}
		}
	}

	// Projection pushdown: each source extracts only the join key and the
	// columns the select list needs from it.
	left.need(lcol.Name.String())
	right.need(rcol.Name.String())
	for _, se := range sel.GetColumns() {
		switch e := se.(type) {
		case *sqlparser.StarExpr:
			switch e.TableName.Name.String() {
			case "":
				left.star, right.star = true, true
			case left.alias:
				left.star = true
			case right.alias:
				right.star = true
			}
		case *sqlparser.AliasedExpr:
			if col, ok := e.Expr.(*sqlparser.ColName); ok {
				switch col.Qualifier.Name.String() {
				case left.alias:
					left.need(col.Name.String())
				case right.alias:
					right.need(col.Name.String())
				}
			}
		}
	}

	plan := &ExecutionPlan{}
	for i, src := range []*source{left, right} {
		q, args, err := src.query()
		if err != nil {
			return nil, err
		}
		plan.Steps = append(plan.Steps, ExecutionStep{
			ID:       i + 1,
			Type:     "SCAN",
			Database: src.db,
			Alias:    src.alias,
			Query:    q,
			Args:     args,
		})
	}
	if meta.HasJoin {
		plan.Steps = append(plan.Steps, ExecutionStep{
			ID:        3,
			Type:      "JOIN",
			DependsOn: []int{1, 2},
			LeftKey:   left.alias + "." + lcol.Name.String(),
			RightKey:  right.alias + "." + rcol.Name.String(),
		})
	}

	for _, se := range sel.GetColumns() {
		switch e := se.(type) {
		case *sqlparser.StarExpr:
			if q := e.TableName.Name.String(); q != "" {
				plan.Projection = append(plan.Projection, q+".*")
			} else {
				plan.Projection = append(plan.Projection, "*")
			}
			plan.Labels = append(plan.Labels, "")
		case *sqlparser.AliasedExpr:
			col, ok := e.Expr.(*sqlparser.ColName)
			if !ok || col.Qualifier.Name.IsEmpty() {
				return nil, fmt.Errorf("%w: select list must contain qualified columns", ErrUnsupportedFederation)
			}
			plan.Projection = append(plan.Projection, col.Qualifier.Name.String()+"."+col.Name.String())
			plan.Labels = append(plan.Labels, e.As.String())
		}
	}
	return plan, nil
}

type source struct {
	db, table, alias string
	raw              string // original query text, to tell quoted identifiers apart
	filters          []sqlparser.Expr
	// columns to extract; nil means every column (SELECT *).
	columns []string
	star    bool
}

func (s *source) need(col string) {
	for _, c := range s.columns {
		if c == col {
			return
		}
	}
	s.columns = append(s.columns, col)
}

func scanSource(te sqlparser.TableExpr, raw string) (*source, error) {
	at, ok := te.(*sqlparser.AliasedTableExpr)
	if !ok {
		return nil, ErrUnsupportedFederation
	}
	name, ok := at.Expr.(sqlparser.TableName)
	if !ok {
		return nil, ErrUnsupportedFederation
	}
	s := &source{db: name.Qualifier.String(), table: name.Name.String(), alias: at.As.String(), raw: raw}
	if s.db == "" {
		s.db = "default"
	}
	if s.alias == "" {
		s.alias = s.table
	}
	return s, nil
}

// query renders the per-source extraction query. Identifiers are quoted
// where needed and every literal becomes a bind parameter, so no value is
// ever re-escaped for the target dialect.
func (s *source) query() (string, []any, error) {
	cols := "*"
	if !s.star {
		quoted := make([]string, len(s.columns))
		for i, c := range s.columns {
			quoted[i] = sqlparser.String(sqlparser.NewIdentifierCI(columnName(c, s.raw)))
		}
		cols = strings.Join(quoted, ", ")
	}
	q := "SELECT " + cols + " FROM " + sqlparser.String(sqlparser.NewIdentifierCS(s.table))
	var args []any
	if len(s.filters) > 0 {
		parts := make([]string, len(s.filters))
		for i, f := range s.filters {
			var err error
			var bound sqlparser.Expr
			if bound, args, err = parameterize(f, args); err != nil {
				return "", nil, err
			}
			parts[i] = sqlparser.String(bound)
		}
		q += " WHERE " + strings.Join(parts, " AND ")
	}
	return q, args, nil
}

// parameterize returns a copy of e whose literals are replaced by :vN
// placeholders numbered after the values already in args.
func parameterize(e sqlparser.Expr, args []any) (sqlparser.Expr, []any, error) {
	var err error
	out := sqlparser.Rewrite(sqlparser.CloneExpr(e), func(c *sqlparser.Cursor) bool {
		switch n := c.Node().(type) {
		case *sqlparser.Argument:
			err = fmt.Errorf("%w: bind parameters are not supported", ErrUnsupportedFederation)
			return false
		case *sqlparser.Literal:
			var val any
			switch n.Type {
			case sqlparser.StrVal, sqlparser.DateVal, sqlparser.TimeVal, sqlparser.TimestampVal:
				val = n.Val
			case sqlparser.IntVal:
				i, perr := strconv.ParseInt(n.Val, 10, 64)
				if perr != nil {
					err = fmt.Errorf("%w: integer %s out of range", ErrUnsupportedFederation, n.Val)
					return false
				}
				val = i
			case sqlparser.FloatVal, sqlparser.DecimalVal:
				f, perr := strconv.ParseFloat(n.Val, 64)
				if perr != nil {
					err = perr
					return false
				}
				val = f
			default:
				err = fmt.Errorf("%w: hexadecimal and bit literals are not supported", ErrUnsupportedFederation)
				return false
			}
			args = append(args, val)
			c.Replace(sqlparser.NewArgument("v" + strconv.Itoa(len(args))))
		}
		return err == nil
	}, nil)
	if err != nil {
		return nil, nil, err
	}
	return out.(sqlparser.Expr), args, nil
}

func conjuncts(e sqlparser.Expr) []sqlparser.Expr {
	if n, ok := e.(*sqlparser.AndExpr); ok {
		return append(conjuncts(n.Left), conjuncts(n.Right)...)
	}
	return []sqlparser.Expr{e}
}

// ownerOf returns the single table alias referenced by e, or "" if e
// references no column or more than one table.
func ownerOf(e sqlparser.Expr) string {
	owner, mixed := "", false
	_ = sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		if c, ok := node.(*sqlparser.ColName); ok {
			q := c.Qualifier.Name.String()
			if owner == "" {
				owner = q
			} else if owner != q {
				mixed = true
			}
		}
		return true, nil
	}, e)
	if mixed {
		return ""
	}
	return owner
}

// unqualified returns a copy of e with column qualifiers removed, so that it
// can be sent to the source that owns the table.
//
// Column references are replaced by new nodes rather than modified:
// Vitess's CloneExpr shares *ColName nodes between copies, and the original
// tree belongs to the parse cache.
func unqualified(e sqlparser.Expr, raw string) sqlparser.Expr {
	out := sqlparser.Rewrite(sqlparser.CloneExpr(e), func(c *sqlparser.Cursor) bool {
		if col, ok := c.Node().(*sqlparser.ColName); ok {
			c.Replace(&sqlparser.ColName{Name: sqlparser.NewIdentifierCI(columnName(col.Name.String(), raw))})
		}
		return true
	}, nil)
	return out.(sqlparser.Expr)
}

// columnName returns the column name as the source will resolve it. Column
// names are case-insensitive in MySQL and folded to lower case by
// PostgreSQL unless quoted, so an unquoted name is lower-cased; a name the
// query quoted keeps its case. Generated SQL may quote keyword-like names,
// and PostgreSQL would then compare them case-sensitively.
func columnName(name, raw string) string {
	if strings.Contains(raw, "`"+name+"`") || strings.Contains(raw, `"`+name+`"`) {
		return name
	}
	return strings.ToLower(name)
}
