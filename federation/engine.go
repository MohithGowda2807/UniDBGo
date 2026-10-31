package federation

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Dheeran-git/UniDBGo/internal"
	"github.com/Dheeran-git/UniDBGo/parser"
	"github.com/Dheeran-git/UniDBGo/planner"
)

// Row representation for in-memory merging. Keys are qualified as
// "alias.column".
type Row map[string]any

// FederationEngine executes multi-database plans. Sources maps the database
// name used in queries (e.g. "postgres", "mysql") to a live connection. A
// connection that reports its driver through a Driver() string method (as
// *api.DB does) gets SQL in that driver's dialect; others get MySQL syntax.
type FederationEngine struct {
	Sources map[string]internal.Connection
}

func dialectOf(c internal.Connection) parser.Dialect {
	if d, ok := c.(interface{ Driver() string }); ok {
		return parser.DialectOf(d.Driver())
	}
	return parser.MySQL
}

// NewEngine creates a federation engine over the given named sources.
func NewEngine(sources map[string]internal.Connection) *FederationEngine {
	return &FederationEngine{Sources: sources}
}

// Execute runs every SCAN step concurrently, waits for all of them, then
// evaluates JOIN steps in memory with HashJoinRelations.
func (f *FederationEngine) Execute(ctx context.Context, plan *planner.ExecutionPlan) (internal.Result, error) {
	if len(plan.Steps) == 0 {
		return nil, fmt.Errorf("empty execution plan")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		results  = make(map[int]Relation)
	)
	for _, step := range plan.Steps {
		if step.Type != "SCAN" {
			continue
		}
		wg.Add(1)
		go func(s planner.ExecutionStep) {
			defer wg.Done()
			rel, err := f.executeStep(ctx, s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
					cancel() // abort the sibling extraction
				}
				return
			}
			results[s.ID] = rel
		}(step)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	for _, step := range plan.Steps {
		if step.Type != "JOIN" {
			continue
		}
		if len(step.DependsOn) != 2 {
			return nil, fmt.Errorf("join requires 2 dependencies")
		}
		joined, err := HashJoinRelations(results[step.DependsOn[0]], results[step.DependsOn[1]], step.LeftKey, step.RightKey)
		if err != nil {
			return nil, fmt.Errorf("federation: %w", err)
		}
		results[step.ID] = joined
	}

	final := results[plan.Steps[len(plan.Steps)-1].ID]
	cols, idx, err := project(final, plan.Projection, plan.Labels)
	if err != nil {
		return nil, err
	}
	return &FederationResult{rel: final, cols: cols, idx: idx, current: -1}, nil
}

// executeStep runs one SCAN on its source and materialises the rows, with
// columns qualified by the step alias.
func (f *FederationEngine) executeStep(ctx context.Context, step planner.ExecutionStep) (Relation, error) {
	conn, ok := f.Sources[step.Database]
	if !ok {
		return Relation{}, fmt.Errorf("federation: no source registered for database %q", step.Database)
	}
	res, err := conn.Query(ctx, parser.Bind(step.Query, dialectOf(conn)), step.Args...)
	if err != nil {
		return Relation{}, fmt.Errorf("federation: %s: %w", step.Database, err)
	}
	defer res.Close()

	prefix := ""
	if step.Alias != "" {
		prefix = step.Alias + "."
	}
	raw := res.Columns()
	cols := make([]string, len(raw))
	for i, c := range raw {
		cols[i] = prefix + c
	}
	return MaterializeRelation(res, cols)
}

// MaterializeRelation reads every remaining row of res. Byte slices are
// copied into strings because drivers reuse their buffers.
func MaterializeRelation(res internal.Result, cols []string) (Relation, error) {
	rel := Relation{Columns: cols}
	ptrs := make([]any, len(cols))
	for res.Next() {
		vals := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := res.Scan(ptrs...); err != nil {
			return rel, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		rel.Rows = append(rel.Rows, vals)
	}
	return rel, res.Err()
}

// Materialize reads every remaining row of res into map-based Rows keyed by cols.
func Materialize(res internal.Result, cols []string) ([]Row, error) {
	rel, err := MaterializeRelation(res, cols)
	return rel.Maps(), err
}

// project resolves the select list against the joined relation and returns
// the output column names and their positions. Explicit columns match
// case-insensitively, since PostgreSQL folds unquoted names to lower case.
func project(rel Relation, projection, labels []string) ([]string, []int, error) {
	if len(projection) == 0 {
		idx := make([]int, len(rel.Columns))
		for i := range idx {
			idx[i] = i
		}
		return rel.Columns, idx, nil
	}
	var cols []string
	var idx []int
	for p, want := range projection {
		switch {
		case want == "*":
			for i, c := range rel.Columns {
				cols, idx = append(cols, c), append(idx, i)
			}
		case strings.HasSuffix(want, ".*"):
			prefix := strings.TrimSuffix(want, "*")
			for i, c := range rel.Columns {
				if len(c) > len(prefix) && strings.EqualFold(c[:len(prefix)], prefix) {
					cols, idx = append(cols, c), append(idx, i)
				}
			}
		default:
			i := rel.index(want)
			if i < 0 {
				return nil, nil, fmt.Errorf("federation: unknown column %s", want)
			}
			name := rel.Columns[i]
			if p < len(labels) && labels[p] != "" {
				name = labels[p]
			}
			cols, idx = append(cols, name), append(idx, i)
		}
	}
	return cols, idx, nil
}

// FederationResult implements internal.Result over a materialised relation.
type FederationResult struct {
	rel     Relation
	cols    []string
	idx     []int // position of each output column in rel
	current int
}

func (fr *FederationResult) Columns() []string { return fr.cols }

// Rows returns the projected rows as maps.
func (fr *FederationResult) Rows() []Row {
	out := make([]Row, len(fr.rel.Rows))
	for i, vals := range fr.rel.Rows {
		p := make(Row, len(fr.cols))
		for j, c := range fr.cols {
			p[c] = vals[fr.idx[j]]
		}
		out[i] = p
	}
	return out
}

func (fr *FederationResult) Next() bool {
	fr.current++
	return fr.current < len(fr.rel.Rows)
}

// Scan copies the current row into dest, in Columns() order. Each dest must
// be a *any, *string, *int64, *float64 or *bool.
func (fr *FederationResult) Scan(dest ...any) error {
	if fr.current < 0 || fr.current >= len(fr.rel.Rows) {
		return fmt.Errorf("scan out of bounds")
	}
	if len(dest) != len(fr.cols) {
		return fmt.Errorf("scan: expected %d destinations, got %d", len(fr.cols), len(dest))
	}
	row := fr.rel.Rows[fr.current]
	for i, c := range fr.cols {
		if err := assign(dest[i], row[fr.idx[i]]); err != nil {
			return fmt.Errorf("scan column %s: %w", c, err)
		}
	}
	return nil
}

// Err is always nil: the rows were fully read before the result was built.
func (fr *FederationResult) Err() error { return nil }

func (fr *FederationResult) Close() error {
	return nil
}

func assign(dest, v any) error {
	switch d := dest.(type) {
	case *any:
		*d = v
	case *string:
		if v == nil {
			*d = ""
		} else {
			*d = fmt.Sprint(v)
		}
	case *int64:
		n, ok := toInt64(v)
		if !ok {
			return fmt.Errorf("cannot convert %T to int64", v)
		}
		*d = n
	case *float64:
		f, ok := toFloat64(v)
		if !ok {
			return fmt.Errorf("cannot convert %T to float64", v)
		}
		*d = f
	case *bool:
		b, ok := v.(bool)
		if !ok {
			n, isNum := toInt64(v)
			if !isNum {
				return fmt.Errorf("cannot convert %T to bool", v)
			}
			b = n != 0
		}
		*d = b
	default:
		return fmt.Errorf("unsupported destination %T", dest)
	}
	return nil
}
