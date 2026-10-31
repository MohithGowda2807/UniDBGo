// Package cache holds query results for a limited time.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/Dheeran-git/UniDBGo/federation"
)

// DefaultMaxEntries bounds the cache when NewEngine is used.
const DefaultMaxEntries = 1024

type CacheEntry struct {
	Result    []federation.Row
	ExpiresAt time.Time
}

// Engine is a TTL cache of query results bounded to MaxEntries. When it is
// full, expired entries are dropped first and, if none expired, the entry
// closest to expiry is evicted.
type Engine struct {
	cache      map[string]CacheEntry
	maxEntries int
	mu         sync.RWMutex
}

func NewEngine() *Engine {
	return NewBoundedEngine(DefaultMaxEntries)
}

// NewBoundedEngine creates a cache holding at most maxEntries results.
func NewBoundedEngine(maxEntries int) *Engine {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &Engine{
		cache:      make(map[string]CacheEntry),
		maxEntries: maxEntries,
	}
}

// hash keys on the query and the type and value of each argument, so that
// e.g. the string "1" and the integer 1 do not collide.
func (e *Engine) hash(query string, args []any) string {
	h := sha256.New()
	h.Write([]byte(query))
	for _, a := range args {
		fmt.Fprintf(h, "\x00%T\x00%v", a, a)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (e *Engine) Get(query string, args []any) ([]federation.Row, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	key := e.hash(query, args)
	val, ok := e.cache[key]
	if ok && time.Now().Before(val.ExpiresAt) {
		return val.Result, true
	}
	return nil, false
}

func (e *Engine) Set(query string, args []any, result []federation.Row, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := e.hash(query, args)
	if _, exists := e.cache[key]; !exists && len(e.cache) >= e.maxEntries {
		e.evict()
	}
	e.cache[key] = CacheEntry{
		Result:    result,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// evict removes expired entries, or the entry closest to expiry if none has
// expired. Caller holds mu.
func (e *Engine) evict() {
	now := time.Now()
	oldestKey := ""
	var oldest time.Time
	for k, v := range e.cache {
		if !now.Before(v.ExpiresAt) {
			delete(e.cache, k)
			continue
		}
		if oldestKey == "" || v.ExpiresAt.Before(oldest) {
			oldestKey, oldest = k, v.ExpiresAt
		}
	}
	if len(e.cache) >= e.maxEntries && oldestKey != "" {
		delete(e.cache, oldestKey)
	}
}

// Len reports the number of cached entries, including expired ones not yet evicted.
func (e *Engine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

// Invalidate drops every entry; call it after any write.
func (e *Engine) Invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cache = make(map[string]CacheEntry)
}
