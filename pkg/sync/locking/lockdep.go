// Copyright 2022 The gVisor Authors.
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

package locking

import (
	"fmt"
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/log"
)

var classMap classAtomicPtrMap

// NewMutexClass allocates a new mutex class.
func NewMutexClass(t reflect.Type) *MutexClass {
	c := &MutexClass{}
	classMap.Store(c, &t)
	return c
}

// MutexClass describes dependencies of a specific class.
type MutexClass struct {
	// ancestors are locks that are locked before the current class.
	ancestors ancestorsAtomicPtrMap
	// subclasses is the list of sub-classes that are used to handle nested locks.
	subclasses subclassAtomicPtrMap
}

type goroutineLocks map[*MutexClass]bool

var routineLocks goroutineLocksAtomicPtrMap

// checkLock checks that class isn't in ancestors of prevClass.
func checkLock(class *MutexClass, prevClass *MutexClass, chain []*MutexClass) {
	chain = append(chain, prevClass)
	if c := prevClass.ancestors.Load(class); c != nil {
		var b strings.Builder
		fmt.Fprintf(&b, "WARNING: circular locking detected: %s -> %s:\n%s\n",
			*classMap.Load(chain[0]), *classMap.Load(class), log.Stacks(false))

		fmt.Fprintf(&b, "known lock chain: ")
		c := class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "%s -> ", *classMap.Load(c))
			c = chain[i]
		}
		fmt.Fprintf(&b, "%s\n", *classMap.Load(chain[0]))
		c = class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "\n====== %s -> %s =====\n%s",
				*classMap.Load(c), *classMap.Load(chain[i]), *chain[i].ancestors.Load(c))
			c = chain[i]
		}
		panic(b.String())
	}
	prevClass.ancestors.RangeRepeatable(func(parentClass *MutexClass, stacks *string) bool {
		// The recursion is fine here. If it fails, you need to reduce
		// a number of nested locks.
		checkLock(class, parentClass, chain)
		return true
	})
}

// AddGLock records a lock to the current goroutine and updates dependences.
func AddGLock(class *MutexClass, subclass uint32) {
	gid := goid.Get()

	if subclass != 0 {
		var c *MutexClass
		if c = class.subclasses.Load(subclass); c == nil {
			t := classMap.Load(class)
			c = NewMutexClass(*t)
			class.subclasses.Store(subclass, c)
		}
		class = c
	}
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		locks := goroutineLocks(make(map[*MutexClass]bool))
		locks[class] = true
		routineLocks.Store(gid, &locks)
		return
	}

	// Check dependencies and add locked mutexes to the ancestors list.
	for prevClass := range *currentLocks {
		if prevClass == class {
			panic(fmt.Sprintf("nested locking: %s:\n%s", *classMap.Load(class), log.Stacks(false)))
		}
		checkLock(class, prevClass, nil)

		if c := class.ancestors.Load(prevClass); c == nil {
			stacks := string(log.Stacks(false))
			class.ancestors.Store(prevClass, &stacks)
		}
	}
	(*currentLocks)[class] = true

}

// DelGLock deletes a lock from the current goroutine.
func DelGLock(class *MutexClass, subclass uint32) {
	origClass := class
	if subclass != 0 {
		class = class.subclasses.Load(subclass)
	}
	gid := goid.Get()
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		panic("the current goroutine doesn't have locks")
	}
	if _, ok := (*currentLocks)[class]; !ok {
		var b strings.Builder
		fmt.Fprintf(&b, "unbalance unlock: %s:%d:\n", *classMap.Load(origClass), subclass)
		fmt.Fprintf(&b, "Current locks:\n")
		for c := range *currentLocks {
			fmt.Fprintf(&b, "\t%s\n", *classMap.Load(c))
		}
		panic(b.String())
	}

	delete(*currentLocks, class)
	if len(*currentLocks) == 0 {
		routineLocks.Store(gid, nil)
	}
}
