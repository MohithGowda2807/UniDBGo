package internal

import (
	"fmt"
	"sync"
)

var (
	driverRegistry = make(map[string]Driver)
	registryMu     sync.RWMutex
)

// RegisterDriver registers a new driver by name.
func RegisterDriver(name string, driver Driver) {
	registryMu.Lock()
	defer registryMu.Unlock()
	driverRegistry[name] = driver
}

// GetDriver retrieves a registered driver by name.
func GetDriver(name string) (Driver, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	d, ok := driverRegistry[name]
	if !ok {
		return nil, fmt.Errorf("driver not found: %s", name)
	}
	return d, nil
}
