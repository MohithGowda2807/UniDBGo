package bench

import (
	"fmt"
	"math/rand"

	"github.com/Dheeran-git/UniDBGo/router"
)

var (
	tables  = []string{"users", "orders", "products", "events", "invoices", "sessions_log", "payments", "reviews", "inventory", "shipments"}
	columns = []string{"id", "name", "email", "status", "total", "created_at", "price", "user_id", "country", "quantity", "rating", "payload", "updated_at"}
	jsonKey = []string{"name", "city", "plan", "device", "tags", "source", "version"}
)

// RouterCorpus generates labelled queries for PostgreSQL, MySQL and MongoDB.
// Dialect-specific constructs are mixed with generic SQL, and a fraction
// (ambiguousShare) of the SQL queries use only generic syntax that is valid in
// both relational dialects; those are labelled with the engine they were
// issued against, so they cannot be classified from syntax alone.
func RouterCorpus(seed int64, nPG, nMySQL, nMongo int, ambiguousShare float64) []router.TrainingRecord {
	g := gen{rand.New(rand.NewSource(seed))}
	var out []router.TrainingRecord
	for i := 0; i < nPG; i++ {
		q := g.pgQuery()
		if g.r.Float64() < ambiguousShare {
			q = g.genericSQL()
		}
		out = append(out, router.TrainingRecord{Query: q, Database: "postgres", Dialect: "PostgreSQL"})
	}
	for i := 0; i < nMySQL; i++ {
		q := g.mysqlQuery()
		if g.r.Float64() < ambiguousShare {
			q = g.genericSQL()
		}
		out = append(out, router.TrainingRecord{Query: q, Database: "mysql", Dialect: "MySQL"})
	}
	for i := 0; i < nMongo; i++ {
		out = append(out, router.TrainingRecord{Query: g.mongoQuery(), Database: "mongodb", Dialect: "MQL"})
	}
	g.r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (g gen) tbl() string { return g.pick(tables) }
func (g gen) col() string { return g.pick(columns) }

func (g gen) genericSQL() string {
	t, c := g.tbl(), g.col()
	switch g.r.Intn(6) {
	case 0:
		return fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = %d ORDER BY %s", c, g.col(), t, g.col(), g.n(1, 9999), c)
	case 1:
		return fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s > %d", t, c, g.n(1, 500))
	case 2:
		return fmt.Sprintf("UPDATE %s SET %s = '%s' WHERE id = %d", t, c, g.word(), g.n(1, 9999))
	case 3:
		return fmt.Sprintf("DELETE FROM %s WHERE %s < %d", t, c, g.n(1, 9999))
	case 4:
		return fmt.Sprintf("SELECT a.%s, b.%s FROM %s a JOIN %s b ON a.id = b.%s WHERE a.%s IN (%d, %d)", c, g.col(), t, g.tbl(), "user_id", g.col(), g.n(1, 99), g.n(100, 999))
	}
	return fmt.Sprintf("INSERT INTO %s (%s, %s) VALUES ('%s', %d)", t, c, g.col(), g.word(), g.n(1, 999))
}

func (g gen) pgQuery() string {
	t, c, k := g.tbl(), g.col(), g.pick(jsonKey)
	switch g.r.Intn(14) {
	case 0:
		return fmt.Sprintf("SELECT %s, %s FROM %s WHERE id = $1", c, g.col(), t)
	case 1:
		return fmt.Sprintf("SELECT %s->>'%s' AS %s FROM %s WHERE %s->'%s' IS NOT NULL", "payload", k, k, t, "payload", k)
	case 2:
		return fmt.Sprintf("SELECT * FROM %s WHERE %s ILIKE $1 LIMIT %d OFFSET %d", t, c, g.n(5, 50), g.n(0, 500))
	case 3:
		return fmt.Sprintf("INSERT INTO %s (%s, %s) VALUES ($1, $2) RETURNING id", t, c, g.col())
	case 4:
		return fmt.Sprintf("SELECT %s::text, %s::numeric(10,2) FROM %s", c, g.col(), t)
	case 5:
		return fmt.Sprintf("SELECT DISTINCT ON (%s) %s, %s FROM %s ORDER BY %s, created_at DESC", c, c, g.col(), t, c)
	case 6:
		return fmt.Sprintf("SELECT * FROM %s WHERE created_at > NOW() - INTERVAL '%d days'", t, g.n(1, 90))
	case 7:
		return fmt.Sprintf("INSERT INTO %s (id, %s) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET %s = EXCLUDED.%s", t, c, c, c)
	case 8:
		return fmt.Sprintf("SELECT %s, string_agg(%s, ', ') FROM %s GROUP BY %s", c, g.col(), t, c)
	case 9:
		return fmt.Sprintf("SELECT * FROM %s WHERE id = ANY($1::int[])", t)
	case 10:
		return fmt.Sprintf("SELECT jsonb_build_object('%s', %s) FROM %s WHERE %s = $1", k, c, t, g.col())
	case 11:
		return fmt.Sprintf("SELECT g FROM generate_series(1, %d) AS g", g.n(10, 1000))
	case 12:
		return fmt.Sprintf("UPDATE %s SET %s = $1 WHERE id = $2 RETURNING *", t, c)
	}
	return fmt.Sprintf("SELECT \"%s\", array_agg(%s) FROM \"%s\" GROUP BY \"%s\"", c, g.col(), t, c)
}

func (g gen) mysqlQuery() string {
	t, c, k := g.tbl(), g.col(), g.pick(jsonKey)
	switch g.r.Intn(14) {
	case 0:
		return fmt.Sprintf("SELECT `%s`, `%s` FROM `%s` WHERE `id` = ?", c, g.col(), t)
	case 1:
		return fmt.Sprintf("SELECT JSON_EXTRACT(payload, '$.%s') FROM %s WHERE id = ?", k, t)
	case 2:
		return fmt.Sprintf("SELECT * FROM %s ORDER BY %s DESC LIMIT %d, %d", t, c, g.n(0, 500), g.n(5, 50))
	case 3:
		return fmt.Sprintf("INSERT INTO %s (%s, %s) VALUES (?, ?) ON DUPLICATE KEY UPDATE %s = VALUES(%s)", t, c, g.col(), c, c)
	case 4:
		return fmt.Sprintf("SELECT IFNULL(%s, 0) FROM %s WHERE %s = ?", c, t, g.col())
	case 5:
		return fmt.Sprintf("SELECT %s, GROUP_CONCAT(%s SEPARATOR ',') FROM %s GROUP BY %s", c, g.col(), t, c)
	case 6:
		return fmt.Sprintf("SELECT * FROM %s WHERE created_at > DATE_SUB(NOW(), INTERVAL %d DAY)", t, g.n(1, 90))
	case 7:
		return fmt.Sprintf("REPLACE INTO %s (id, %s) VALUES (?, ?)", t, c)
	case 8:
		return fmt.Sprintf("SELECT SQL_CALC_FOUND_ROWS * FROM %s LIMIT %d", t, g.n(5, 50))
	case 9:
		return fmt.Sprintf("SELECT UNIX_TIMESTAMP(%s) FROM %s WHERE id = ?", "created_at", t)
	case 10:
		return fmt.Sprintf("SELECT * FROM `%s` STRAIGHT_JOIN `%s` ON `%s`.id = `%s`.user_id", t, g.tbl(), t, t)
	case 11:
		return fmt.Sprintf("CREATE TABLE `%s_copy` (id INT AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB", t)
	case 12:
		return fmt.Sprintf("UPDATE `%s` SET `%s` = ? WHERE `id` = ? LIMIT 1", t, c)
	}
	return fmt.Sprintf("SELECT %s FROM %s WHERE %s REGEXP '^%s' LIMIT %d", c, t, g.col(), g.word(), g.n(5, 50))
}

func (g gen) mongoQuery() string {
	t, c := g.tbl(), g.col()
	switch g.r.Intn(8) {
	case 0:
		return fmt.Sprintf(`{ "find": "%s", "filter": { "%s": { "$gt": %d } } }`, t, c, g.n(1, 999))
	case 1:
		return fmt.Sprintf(`{ "find": "%s", "filter": { "%s": "%s" }, "limit": %d }`, t, c, g.word(), g.n(1, 100))
	case 2:
		return fmt.Sprintf(`{ "aggregate": "%s", "pipeline": [ { "$match": { "%s": { "$in": ["%s", "%s"] } } }, { "$group": { "_id": "$%s", "n": { "$sum": 1 } } } ] }`, t, c, g.word(), g.word(), g.col())
	case 3:
		return fmt.Sprintf(`{ "update": "%s", "updates": [ { "q": { "_id": %d }, "u": { "$set": { "%s": "%s" } } } ] }`, t, g.n(1, 9999), c, g.word())
	case 4:
		return fmt.Sprintf(`{ "insert": "%s", "documents": [ { "%s": "%s", "%s": %d } ] }`, t, c, g.word(), g.col(), g.n(1, 999))
	case 5:
		return fmt.Sprintf(`{ "count": "%s", "query": { "%s": { "$regex": "^%s" } } }`, t, c, g.word())
	case 6:
		return fmt.Sprintf(`db.%s.find({ %s: { $lte: %d } }).sort({ %s: -1 })`, t, c, g.n(1, 999), g.col())
	}
	return fmt.Sprintf(`{ "aggregate": "%s", "pipeline": [ { "$lookup": { "from": "%s", "localField": "%s", "foreignField": "_id", "as": "j" } }, { "$limit": %d } ] }`, t, g.tbl(), c, g.n(1, 100))
}
