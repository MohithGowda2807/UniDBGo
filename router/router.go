package router

import (
	"github.com/Dheeran-git/UniDBGo/planner"
)

// Route maps a step to a specific database and SQL dialect
type Route struct {
	StepID         int
	Database       string
	CommandDialect string
	Confidence     float64
}

type Router interface {
	Route(plan *planner.ExecutionPlan) ([]Route, error)
}

type DefaultRouter struct{}

func (r *DefaultRouter) Route(plan *planner.ExecutionPlan) ([]Route, error) {
	var routes []Route

	for _, step := range plan.Steps {
		if step.Type == "SCAN" || step.Type == "DDL" || step.Type == "META" {
			routes = append(routes, Route{
				StepID:         step.ID,
				Database:       step.Database,
				CommandDialect: "SQL", // Default fallback
				Confidence:     1,
			})
		}
	}

	return routes, nil
}

var (
	// ActiveRouter is the global router instance
	ActiveRouter Router
)

func init() {
	// Fall back to default
	ActiveRouter = &DefaultRouter{}
}

// InitAIRouter initializes the AI router as the primary ActiveRouter.
func InitAIRouter(dbFilePath string) error {
	air, err := NewAIRouter(dbFilePath)
	if err != nil {
		return err
	}
	ActiveRouter = air
	return nil
}
