// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build race

package sync

import deadlock "github.com/sasha-s/go-deadlock"

// Aliases of deadlock library types.
type (
	// Mutex is an alias of deadlock.Mutex.
	Mutex = deadlock.Mutex

	// RWMutex is an alias of deadlock.Mutex.
	RWMutex = deadlock.RWMutex

	// Cond is an alias of deadlock.Cond.
	Cond = deadlock.Cond

	// Locker is an alias of deadlock.Locker.
	Locker = deadlock.Locker

	// Once is an alias of deadlock.Once.
	Once = deadlock.Once

	// Pool is an alias of deadlock.Pool.
	Pool = deadlock.Pool

	// WaitGroup is an alias of deadlock.WaitGroup.
	WaitGroup = deadlock.WaitGroup

	// Map is an alias of deadlock.Map.
	Map = deadlock.Map
)
