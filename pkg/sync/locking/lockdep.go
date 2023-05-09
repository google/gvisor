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

// NewMutexClass allocates a new mutex class.
func NewMutexClass(t reflect.Type, lockNames []string) *MutexClass {
	c := &MutexClass{
		typ:               t,
		nestedLockNames:   lockNames,
		nestedLockClasses: make([]*MutexClass, len(lockNames)),
	}
	for i := range lockNames {
		c.nestedLockClasses[i] = NewMutexClass(t, nil)
		c.nestedLockClasses[i].lockName = lockNames[i]
	}
	return c
}

// MutexClass describes dependencies of a specific class.
type MutexClass struct {
	// The type of the mutex.
	typ reflect.Type

	// Name of the nested lock of the above type.
	lockName string

	// ancestors are locks that are locked before the current class.
	ancestors ancestorsAtomicPtrMap
	// nestedLockNames is a list of names for nested locks which are considered difference instances
	// of the same lock class.
	nestedLockNames []string
	// namedLockClasses is a list of MutexClass instances of the same mutex class, but that are
	// considered OK to lock simultaneously with each other, as well as with this mutex class.
	// This is used for nested locking, where multiple instances of the same lock class are used
	// simultaneously.
	// Maps one-to-one with nestedLockNames.
	nestedLockClasses []*MutexClass
}

func (m *MutexClass) String() string {
	if m.lockName == "" {
		return m.typ.String()
	}
	return fmt.Sprintf("%s[%s]", m.typ.String(), m.lockName)
}

type goroutineLocks map[*MutexClass]bool

var routineLocks goroutineLocksAtomicPtrMap

// maxChainLen is the maximum length of a lock chain.
const maxChainLen = 32

// checkLock checks that class isn't in the ancestors of prevClass.
func checkLock(class *MutexClass, prevClass *MutexClass, chain []*MutexClass) {
	chain = append(chain, prevClass)
	if len(chain) >= maxChainLen {
		// It can be a race condition with another thread that added
		// the lock to the graph but don't complete the validation.
		var b strings.Builder
		fmt.Fprintf(&b, "WARNING: The maximum lock depth has been reached: %s", chain[0])
		for i := 1; i < len(chain); i++ {
			fmt.Fprintf(&b, "-> %s", chain[i])
		}
		log.Warningf("%s", b.String())
		return
	}
	if c := prevClass.ancestors.Load(class); c != nil {
		var b strings.Builder
		fmt.Fprintf(&b, "WARNING: circular locking detected: %s -> %s:\n%s\n",
			chain[0], class, log.LocalStack(3))

		fmt.Fprintf(&b, "known lock chain: ")
		c := class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "%s -> ", c)
			c = chain[i]
		}
		fmt.Fprintf(&b, "%s\n", chain[0])
		c = class
		for i := len(chain) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "\n====== %s -> %s =====\n%s",
				c, chain[i], *chain[i].ancestors.Load(c))
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

// AddGLock records a lock to the current goroutine and updates dependencies.
func AddGLock(class *MutexClass, lockNameIndex int) {
	gid := goid.Get()

	if lockNameIndex != -1 {
		class = class.nestedLockClasses[lockNameIndex]
	}
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		locks := goroutineLocks(make(map[*MutexClass]bool))
		locks[class] = true
		routineLocks.Store(gid, &locks)
		return
	}

	if (*currentLocks)[class] {
		panic(fmt.Sprintf("nested locking: %s:\n%s", class, log.LocalStack(2)))
	}
	(*currentLocks)[class] = true
	// Check dependencies and add locked mutexes to the ancestors list.
	for prevClass := range *currentLocks {
		if prevClass == class {
			continue
		}
		checkLock(class, prevClass, nil)

		if c := class.ancestors.Load(prevClass); c == nil {
			stacks := string(log.LocalStack(2))
			class.ancestors.Store(prevClass, &stacks)
		}
	}
}

// DelGLock deletes a lock from the current goroutine.
func DelGLock(class *MutexClass, lockNameIndex int) {
	if lockNameIndex != -1 {
		class = class.nestedLockClasses[lockNameIndex]
	}
	gid := goid.Get()
	currentLocks := routineLocks.Load(gid)
	if currentLocks == nil {
		panic("the current goroutine doesn't have locks")
	}
	if _, ok := (*currentLocks)[class]; !ok {
		var b strings.Builder
		fmt.Fprintf(&b, "Lock not held: %s:\n", class)
		fmt.Fprintf(&b, "Current stack:\n%s\n", string(log.LocalStack(2)))
		fmt.Fprintf(&b, "Current locks:\n")
		for c := range *currentLocks {
			heldToClass := class.ancestors.Load(c)
			classToHeld := c.ancestors.Load(class)
			if heldToClass == nil && classToHeld == nil {
				fmt.Fprintf(&b, "\t- Holding lock: %s (no dependency to/from %s found)\n", c, class)
			} else if heldToClass != nil && classToHeld != nil {
				fmt.Fprintf(&b, "\t- Holding lock: %s (mutual dependency with %s found, this should never happen)\n", c, class)
			} else if heldToClass != nil && classToHeld == nil {
				fmt.Fprintf(&b, "\t- Holding lock: %s (dependency: %s -> %s)\n", c, c, class)
				fmt.Fprintf(&b, "%s\n\n", *heldToClass)
			} else if heldToClass == nil && classToHeld != nil {
				fmt.Fprintf(&b, "\t- Holding lock: %s (dependency: %s -> %s)\n", c, class, c)
				fmt.Fprintf(&b, "%s\n\n", *classToHeld)
			}
		}
		fmt.Fprintf(&b, "** End of locks held **\n")
		panic(b.String())
	}

	delete(*currentLocks, class)
	if len(*currentLocks) == 0 {
		routineLocks.Store(gid, nil)
	}
}
