// Copyright 2018 The gVisor Authors.
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

// +build amd64

package pagetables

// Visitor is a generic type.
type Visitor interface {
	// visit is called on each PTE.
	visit(start uintptr, pte *PTE, align uintptr)

	// requiresAlloc indicates that new entries should be allocated within
	// the walked range.
	requiresAlloc() bool

	// requiresSplit indicates that entries in the given range should be
	// split if they are huge or jumbo pages.
	requiresSplit() bool
}

// IterateRange iterates over all appropriate levels of page tables for the given range.
//
// If requiresAlloc is true, then Set _must_ be called on all given PTEs. The
// exception is super pages. If a valid super page (huge or jumbo) cannot be
// installed, then the walk will continue to individual entries.
//
// This algorithm will attempt to maximize the use of super pages whenever
// possible. Whether a super page is provided will be clear through the range
// provided in the callback.
//
// Note that if requiresAlloc is true, then no gaps will be present. However,
// if alloc is not set, then the iteration will likely be full of gaps.
//
// Note that this function should generally be avoided in favor of Map, Unmap,
// etc. when not necessary.
//
// Precondition: start must be page-aligned.
//
// Precondition: start must be less than end.
//
// Precondition: If requiresAlloc is true, then start and end should not span
// non-canonical ranges. If they do, a panic will result.
//
// +checkescape
//
//go:nosplit
func IterateRange(pageTables *PageTables, visitor Visitor, start, end uintptr) {
	if start%pteSize != 0 {
		panic("unaligned start")
	}
	if end < start {
		panic("start > end")
	}
	if start < lowerTop {
		if end <= lowerTop {
			IterateRangeCanonical(pageTables, visitor, start, end)
		} else if end > lowerTop && end <= upperBottom {
			if visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			IterateRangeCanonical(pageTables, visitor, start, lowerTop)
		} else {
			if visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			IterateRangeCanonical(pageTables, visitor, start, lowerTop)
			IterateRangeCanonical(pageTables, visitor, upperBottom, end)
		}
	} else if start < upperBottom {
		if end <= upperBottom {
			if visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
		} else {
			if visitor.requiresAlloc() {
				panic("alloc spans non-canonical range")
			}
			IterateRangeCanonical(pageTables, visitor, upperBottom, end)
		}
	} else {
		IterateRangeCanonical(pageTables, visitor, start, end)
	}
}

// next returns the next address quantized by the given size.
//
//go:nosplit
func next(start uintptr, size uintptr) uintptr {
	start &= ^(size - 1)
	start += size
	return start
}
