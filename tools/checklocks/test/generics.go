package test

import "sync"

// genericGuardStruct demonstrates a generic struct whose field is guarded by a mutex.
type genericGuardStruct[T any] struct {
	mu sync.Mutex
	// +checklocks:mu
	value T
}

// genericValidLockedAccess writes while holding the guard lock. This should be OK.
func genericValidLockedAccess[T any](g *genericGuardStruct[T], v T) {
	g.mu.Lock()
	g.value = v
	g.mu.Unlock()
}

// genericInvalidUnlockedWrite writes without holding the lock. This should fail.
func genericInvalidUnlockedWrite[T any](g *genericGuardStruct[T], v T) {
	g.value = v // +checklocksfail
}

// genericInvalidUnlockedRead reads without holding the lock. This should fail.
func genericInvalidUnlockedRead[T any](g *genericGuardStruct[T]) T {
	return g.value // +checklocksfail
}

// genericInstantiate exists solely to instantiate genericGuardStruct so that the
// analyzer observes an instantiation and does not warn about the mutex field
// itself.
func genericInstantiate() {
	var _ genericGuardStruct[int]
}
