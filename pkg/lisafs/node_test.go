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

package lisafs

import (
	"fmt"
	"testing"
)

func TestLookup(t *testing.T) {
	for _, numChildren := range []int{
		numStaticChildren,     // For static children.
		2 * numStaticChildren, // For dynamic children.
	} {
		t.Run(fmt.Sprintf("%dChildren", numChildren), func(t *testing.T) {
			s := NewServer()
			defer s.Destroy()
			s.renameMu.RLock()
			defer s.renameMu.RUnlock()
			root := s.root
			root.childrenMu.Lock()

			// truth is the source of truth.
			truth := make(map[string]*Node)

			// Fill node with children.
			for i := 0; i < numChildren; i++ {
				name := fmt.Sprintf("%d", i)
				var child Node
				child.InitLocked(name, root)
				truth[name] = &child
			}

			// Test that lookup finds child correctly.
			for i := 0; i < numChildren; i++ {
				name := fmt.Sprintf("%d", i)
				if got, want := root.LookupChildLocked(name), truth[name]; got != want {
					t.Errorf("incorrect child returned by root: want %p, got %p", want, got)
				}
			}
			root.childrenMu.Unlock()
			for _, child := range truth {
				child.DecRef(nil)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	for _, numChildren := range []int{
		numStaticChildren,     // For static children.
		2 * numStaticChildren, // For dynamic children.
	} {
		t.Run(fmt.Sprintf("%dChildren", numChildren), func(t *testing.T) {
			s := NewServer()
			defer s.Destroy()
			s.renameMu.RLock()
			defer s.renameMu.RUnlock()
			root := s.root
			root.childrenMu.Lock()

			// truth is the source of truth.
			truth := make(map[string]*Node)

			// Fill node with children.
			for i := 0; i < numChildren; i++ {
				name := fmt.Sprintf("%d", i)
				var child Node
				child.InitLocked(name, root)
				truth[name] = &child
			}

			// Now remove them and check if correct node is removed.
			for i := 0; i < numChildren; i++ {
				name := fmt.Sprintf("%d", i)
				if got, want := root.removeChildLocked(name), truth[name]; got != want {
					t.Errorf("root deleted incorrect node: want %p, got %p", want, got)
				}
			}
			root.childrenMu.Unlock()

			// Replacing an unlinked node must survive its final DecRef.
			for name, old := range truth {
				old.opMu.Lock()
				old.markDeletedRecursive()
				old.opMu.Unlock()
				var replacement Node
				root.childrenMu.Lock()
				replacement.InitLocked(name, root)
				root.childrenMu.Unlock()
				old.DecRef(nil)
				root.childrenMu.Lock()
				if got := root.LookupChildLocked(name); got != &replacement {
					t.Errorf("final DecRef removed replacement: got %p, want %p", got, &replacement)
				}
				root.childrenMu.Unlock()
				replacement.DecRef(nil)
			}
		})
	}
}
