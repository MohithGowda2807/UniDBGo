package router

import (
	"log"

	"github.com/Dheeran-git/UniDBGo/planner"
)

// DefaultThreshold is the posterior probability below which a prediction is
// not trusted and the query is sent to the fallback database instead.
const DefaultThreshold = 0.85

// AIRouter routes plan steps in three tiers: an explicit database qualifier
// in the query (e.g. "mysql.orders") always wins; otherwise a multinomial
// Naive Bayes model predicts the dialect, and predictions whose posterior is
// below Threshold go to Fallback.
type AIRouter struct {
	model     *RoutingModel
	db        *CommonDB
	Threshold float64
	Fallback  string
}

// NewAIRouter creates an AIRouter and attempts to load and train the model.
func NewAIRouter(dbFilePath string) (*AIRouter, error) {
	commonDb, err := NewCommonDB(dbFilePath)
	if err != nil {
		return nil, err
	}

	model := NewRoutingModel()
	records := commonDb.GetAllRecords()
	if len(records) > 0 {
		model.Train(records)
		log.Printf("AIRouter initialized: trained on %d records\n", len(records))
	} else {
		// Insert some initial seed data if DB is empty
		for _, s := range SeedData {
			commonDb.AddRecord(s)
		}
		model.Train(commonDb.GetAllRecords())
		log.Printf("AIRouter initialized: seeded and trained on %d records\n", len(SeedData))
	}

	return NewAIRouterWithModel(model, commonDb), nil
}

// NewAIRouterWithModel wraps an already trained model.
func NewAIRouterWithModel(model *RoutingModel, store *CommonDB) *AIRouter {
	return &AIRouter{model: model, db: store, Threshold: DefaultThreshold, Fallback: "default"}
}

// SeedData bootstraps an empty training store.
var SeedData = []TrainingRecord{
	{Query: "SELECT * FROM users LIMIT 10", Database: "postgres", Dialect: "PostgreSQL"},
	{Query: "SELECT * FROM users WHERE id = $1", Database: "postgres", Dialect: "PostgreSQL"},
	{Query: "SELECT data->>'name' FROM configs", Database: "postgres", Dialect: "PostgreSQL"},
	{Query: "SELECT * FROM users ORDER BY id DESC LIMIT 5", Database: "mysql", Dialect: "MySQL"},
	{Query: "SELECT JSON_EXTRACT(data, '$.name') FROM configs", Database: "mysql", Dialect: "MySQL"},
	{Query: "SELECT * FROM `users` WHERE id = ?", Database: "mysql", Dialect: "MySQL"},
	{Query: `{ "find": "users", "filter": { "age": { "$gt": 25 } } }`, Database: "mongodb", Dialect: "MQL"},
}

// Predict exposes the model prediction for a single query.
func (ar *AIRouter) Predict(query string) RoutingPrediction { return ar.model.Predict(query) }

// Route predicts the best target database and dialect for each step.
func (ar *AIRouter) Route(plan *planner.ExecutionPlan) ([]Route, error) {
	var routes []Route

	for _, step := range plan.Steps {
		if step.Type == "JOIN" {
			continue // joins run in memory, not on a backend
		}
		if step.Database != "" && step.Database != "default" {
			routes = append(routes, Route{StepID: step.ID, Database: step.Database, CommandDialect: "SQL", Confidence: 1})
			continue
		}

		prediction := ar.model.Predict(step.Query)
		route := Route{
			StepID:         step.ID,
			Database:       prediction.TargetDatabase,
			CommandDialect: prediction.TargetDialect,
			Confidence:     prediction.Confidence,
		}
		if prediction.Confidence < ar.Threshold {
			route.Database, route.CommandDialect = ar.Fallback, "SQL"
		}
		routes = append(routes, route)
		log.Printf("AIRouter step [%d] -> DB: %s, Dialect: %s (posterior %.3f)\n",
			step.ID, route.Database, route.CommandDialect, prediction.Confidence)
	}

	return routes, nil
}
