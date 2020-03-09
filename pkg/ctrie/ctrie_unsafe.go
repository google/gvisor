// Copyright 2020 The gVisor Authors.
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

package ctrie

import (
	"fmt"
	"sync/atomic"
	"unsafe"
)

// mainNode is a basic pointer.
//
// It points to either an sNode, cNode, iNode, tNode or lNode. These cases are
// distinguished by the first word in the structures. Note that appropriate
// accessors should always be used, which ensure that the expected types are
// exhaustive.
type mainNode unsafe.Pointer

// oldMainNode is used to distinguish the original value.
type oldMainNode unsafe.Pointer

// CTL loads a cNode, tNode or lNode from the given mainNode.
//
// Precondition: *m must not be nil.
func CTL(m *mainNode) (*cNode, *tNode, *lNode, oldMainNode) {
	val := atomic.LoadPointer((*unsafe.Pointer)(m))
	typeDWord := *(*uint32)(val)
	if typeDWord == typeTNode {
		return nil, (*tNode)(val), nil, oldMainNode(val)
	}
	if typeDWord == typeLNode {
		return nil, nil, (*lNode)(val), oldMainNode(val)
	}
	if typeDWord != typeCNode {
		panic(fmt.Sprintf(
			"CTL call failed; unexpected type word %d: expected one of (typeTNode=%d, typeLNode=%d, typeCNode=%d)",
			typeDWord, typeTNode, typeLNode, typeCNode))
	}
	return (*cNode)(val), nil, nil, oldMainNode(val)
}

// IS loads an iNode or sNode from the given mainNode.
//
// Note that this is used for arrays in cNode. Since these can never be changed
// in-place, we don't return the original value for a CAS.
func IS(m *mainNode) (*iNode, *sNode) {
	val := atomic.LoadPointer((*unsafe.Pointer)(m))
	typeDWord := *(*uint32)(val)
	if typeDWord == typeSNode {
		return nil, (*sNode)(val)
	}
	if typeDWord != typeINode {
		panic(fmt.Sprintf(
			"IS call failed; unexpected type word %d: expected one of (typeSNode=%d, typeINode=%d)",
			typeDWord, typeSNode, typeINode))
	}
	return (*iNode)(val), nil
}

// CAS performs a compare and swap operation.
//
// Precondition: *m must not be nil.
func CAS(m *mainNode, orig oldMainNode, newVal mainNode) bool {
	return atomic.CompareAndSwapPointer((*unsafe.Pointer)(m), (unsafe.Pointer)(orig), (unsafe.Pointer)(newVal))
}
