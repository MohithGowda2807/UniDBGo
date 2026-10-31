package mongodb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Dheeran-git/UniDBGo/internal"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func init() {
	internal.RegisterDriver("mongodb", &MongoDriver{})
}

type MongoDriver struct{}

// URI renders config as a MongoDB connection string; URI parameters such as
// authSource or replicaSet are passed through.
func URI(config internal.Config) string {
	u := url.URL{Scheme: "mongodb", Host: net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), Path: "/"}
	if config.Username != "" {
		u.User = url.UserPassword(config.Username, config.Password)
	}
	q := url.Values{}
	for k, v := range config.Params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (d *MongoDriver) Connect(config internal.Config) (internal.Connection, error) {
	clientOptions := options.Client().ApplyURI(URI(config))
	if config.PoolSize > 0 {
		clientOptions.SetMaxPoolSize(uint64(config.PoolSize))
	}

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx, nil); err != nil {
		client.Disconnect(context.Background())
		return nil, err
	}

	db := client.Database(config.Database)

	return &MongoConnection{client: client, db: db}, nil
}

func (d *MongoDriver) Capabilities() internal.Capabilities {
	return internal.Capabilities{
		SupportsSQL:          false, // a SQL subset is translated to find commands
		SupportsTransactions: false,
		SupportsJoins:        false,
		SupportsAggregation:  true,
	}
}

type MongoConnection struct {
	client *mongo.Client
	db     *mongo.Database
}

// Query accepts either a SQL SELECT from the subset handled by Translate, or
// a raw MongoDB command document in Extended JSON such as
// {"find": "users", "filter": {"age": {"$gt": 25}}}.
func (c *MongoConnection) Query(ctx context.Context, query string, args ...any) (internal.Result, error) {
	if strings.HasPrefix(strings.TrimSpace(query), "{") {
		var cmd bson.D
		if err := bson.UnmarshalExtJSON([]byte(query), false, &cmd); err != nil {
			return nil, fmt.Errorf("mongodb: invalid command document: %w", err)
		}
		cur, err := c.db.RunCommandCursor(ctx, cmd)
		if err != nil {
			return nil, err
		}
		return newResult(ctx, cur, nil)
	}

	spec, err := Translate(query, args)
	if err != nil {
		return nil, err
	}
	if spec.HasLimit && spec.Limit == 0 {
		return &mongoResult{cols: spec.Columns, current: -1}, nil
	}
	opts := options.Find()
	if spec.Projection != nil {
		opts.SetProjection(spec.Projection)
	}
	if spec.Sort != nil {
		opts.SetSort(spec.Sort)
	}
	if spec.Limit > 0 {
		opts.SetLimit(spec.Limit)
	}
	if spec.Skip > 0 {
		opts.SetSkip(spec.Skip)
	}
	cur, err := c.db.Collection(spec.Collection).Find(ctx, spec.Filter, opts)
	if err != nil {
		return nil, err
	}
	return newResult(ctx, cur, spec.Columns)
}

func (c *MongoConnection) Exec(ctx context.Context, query string, args ...any) (internal.ExecResult, error) {
	return nil, errors.New("mongodb: write statements are not translated yet")
}

func (c *MongoConnection) BeginTx(ctx context.Context, opts *internal.TxOptions) (internal.Tx, error) {
	return nil, errors.New("mongodb: transactions are not supported through UniDB-Go")
}

func (c *MongoConnection) Close() error {
	return c.client.Disconnect(context.Background())
}

// mongoResult adapts a cursor to internal.Result. Columns are the projected
// fields, or the keys of the first document ("_id" first) for SELECT *.
type mongoResult struct {
	docs    []bson.M
	cols    []string
	current int
}

func newResult(ctx context.Context, cur *mongo.Cursor, cols []string) (*mongoResult, error) {
	defer cur.Close(ctx)
	var docs []bson.M
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	if cols == nil && len(docs) > 0 {
		for k := range docs[0] {
			if k != "_id" {
				cols = append(cols, k)
			}
		}
		sort.Strings(cols)
		if _, ok := docs[0]["_id"]; ok {
			cols = append([]string{"_id"}, cols...)
		}
	}
	return &mongoResult{docs: docs, cols: cols, current: -1}, nil
}

func (r *mongoResult) Columns() []string { return r.cols }

func (r *mongoResult) Next() bool {
	r.current++
	return r.current < len(r.docs)
}

func (r *mongoResult) Scan(dest ...any) error {
	if r.current < 0 || r.current >= len(r.docs) {
		return errors.New("scan out of bounds")
	}
	if len(dest) != len(r.cols) {
		return fmt.Errorf("scan: expected %d destinations, got %d", len(r.cols), len(dest))
	}
	for i, c := range r.cols {
		v := r.docs[r.current][c]
		switch d := dest[i].(type) {
		case *any:
			*d = v
		case *string:
			if v == nil {
				*d = ""
			} else {
				*d = fmt.Sprint(v)
			}
		default:
			return fmt.Errorf("scan: unsupported destination %T", dest[i])
		}
	}
	return nil
}

// Err is always nil: the cursor was fully read when the result was built.
func (r *mongoResult) Err() error { return nil }

func (r *mongoResult) Close() error { return nil }
