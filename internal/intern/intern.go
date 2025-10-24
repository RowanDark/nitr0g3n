package intern

import "sync"

var (
	mu     sync.RWMutex
	values = make(map[string]string)
)

// Intern returns a canonical representation for the provided string.
// It deduplicates repeated values to reduce allocations across the process.
func Intern(s string) string {
	if s == "" {
		return ""
	}

	mu.RLock()
	interned, ok := values[s]
	mu.RUnlock()
	if ok {
		return interned
	}

	mu.Lock()
	defer mu.Unlock()
	if interned, ok := values[s]; ok {
		return interned
	}
	values[s] = s
	return s
}
