// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build lockdep
// +build lockdep

// Package locking package implements lock primitives with the correctness validator.
package locking

import (
	"fmt"
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

var classMap = make(map[*MutexClass]reflect.Type)
var classMapMu sync.Mutex

// NewMutexClass allocates a new lock class.
func NewMutexClass(t reflect.Type) *MutexClass {
	c := &MutexClass{}
	classMapMu.Lock()
	classMap[c] = t
	classMapMu.Unlock()
	c.subclasses = make(map[uint32]*MutexClass)
	return c
}

// LockDependencies describes dependencies for a lock class.
type MutexClass struct {
	mu         sync.Mutex
	parents    map[*MutexClass]string
	subclasses map[uint32]*MutexClass
}

type goroutineLocks map[*MutexClass]bool

var routineLocks goroutineLocksAtomicPtrMap

func checkLock(class *MutexClass, prevClass *MutexClass, chain []*MutexClass) {
	chain = append(chain, prevClass)
	prevClass.mu.Lock()
	defer prevClass.mu.Unlock()
	if prevClass.parents == nil {
		return
	}
	if _, ok := prevClass.parents[class]; ok {
		classMapMu.Lock()
		defer classMapMu.Unlock()

		var b strings.Builder
		fmt.Fprintf(&b, "WARNING: circular locking detected: %s -> %s:\n%s\n", classMap[chain[0]], classMap[class], log.Stacks(false))

		fmt.Fprintf(&b, "known lock chain: ")
		c := class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "%s -> ", classMap[c])
			c = chain[i]
		}
		fmt.Fprintf(&b, "%s\n", classMap[chain[0]])
		c = class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "\n====== %s -> %s =====\n%s", classMap[c], classMap[chain[i]], chain[i].parents[c])
			c = chain[i]
		}
		panic(b.String())
	}
	for parentClass, _ := range prevClass.parents {
		// The recursion is fine here. If it fails, you need to reduce
		// a number of nested locks.
		checkLock(class, parentClass, chain)
	}
}

// AddGLock records a lock to the current goroutine.
func AddGLock(class *MutexClass, subclass uint32) {
	gid := goid.Get()

	if subclass != 0 {
		var ok bool
		var c *MutexClass
		class.mu.Lock()
		if c, ok = class.subclasses[subclass]; !ok {
			classMapMu.Lock()
			t := classMap[class]
			classMapMu.Unlock()
			c = NewMutexClass(t)
			class.subclasses[subclass] = c
		}
		class.mu.Unlock()
		class = c
	}
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		locks := goroutineLocks(make(map[*MutexClass]bool))
		locks[class] = true
		routineLocks.Store(gid, &locks)
		return
	}

	for prevClass, _ := range *currentLocks {
		if prevClass == class {
			classMapMu.Lock()
			defer classMapMu.Unlock()
			panic(fmt.Sprintf("nested locking: %s:\n%s", classMap[class], log.Stacks(false)))
		}
		checkLock(class, prevClass, nil)

		class.mu.Lock()
		if class.parents == nil {
			class.parents = make(map[*MutexClass]string)
		}
		if _, ok := class.parents[prevClass]; !ok {
			class.parents[prevClass] = string(log.Stacks(false))
		}
		class.mu.Unlock()
	}
	(*currentLocks)[class] = true

}

// DelGLock deletes a lock from the current goroutine.
func DelGLock(class *MutexClass, subclass uint32) {
	if subclass != 0 {
		class = class.subclasses[subclass]
	}
	gid := goid.Get()
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		panic("the current goroutine doesn't have locks")
	}
	if _, ok := (*currentLocks)[class]; !ok {
		panic("unlock of an unknow lock")
	}

	delete(*currentLocks, class)
	if len(*currentLocks) == 0 {
		routineLocks.Store(gid, nil)
	}
}
