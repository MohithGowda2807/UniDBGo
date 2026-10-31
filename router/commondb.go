package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// TrainingRecord represents a single query and its optimal target database and executing dialect.
type TrainingRecord struct {
	Query    string `json:"query"`
	Database string `json:"database"`
	Dialect  string `json:"dialect"`
}

// CommonDB provides persistent storage for training queries and outcomes.
type CommonDB struct {
	mu       sync.RWMutex
	filePath string
	records  []TrainingRecord
}

// NewCommonDB initializes a JSON-file backed store.
func NewCommonDB(filePath string) (*CommonDB, error) {
	db := &CommonDB{
		filePath: filePath,
		records:  []TrainingRecord{},
	}
	// A missing file is a fresh store; an unreadable or corrupt one is an error.
	if err := db.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("router: loading training store %s: %w", filePath, err)
	}
	return db, nil
}

// AddRecord adds a new training record to the data store.
func (db *CommonDB) AddRecord(record TrainingRecord) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.records = append(db.records, record)
	return db.save()
}

// GetAllRecords returns all stored training data.
func (db *CommonDB) GetAllRecords() []TrainingRecord {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Return a copy to avoid external mutation
	copied := make([]TrainingRecord, len(db.records))
	copy(copied, db.records)
	return copied
}

// Load reads the records from the JSON file.
func (db *CommonDB) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := os.ReadFile(db.filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &db.records)
}

// save writes the records to the JSON file persistently.
func (db *CommonDB) save() error {
	data, err := json.MarshalIndent(db.records, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(db.filePath, data, 0644)
}
