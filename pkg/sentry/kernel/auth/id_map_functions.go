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

package auth

// idMapFunctions "implements" generic interface segment.Functions for
// idMapSet. An idMapSet maps non-overlapping ranges of contiguous IDs in one
// user namespace to non-overlapping ranges of contiguous IDs in another user
// namespace. Each such ID mapping is implemented as a range-to-value mapping
// in the set such that [range.Start(), range.End()) => [value, value +
// range.Length()).
type idMapFunctions struct{}

func (idMapFunctions) MinKey() uint32 {
	return 0
}

func (idMapFunctions) MaxKey() uint32 {
	return NoID
}

func (idMapFunctions) ClearValue(*uint32) {}

func (idMapFunctions) Merge(r1 idMapRange, val1 uint32, r2 idMapRange, val2 uint32) (uint32, bool) {
	// Mapped ranges have to be contiguous.
	if val1+r1.Length() != val2 {
		return 0, false
	}
	return val1, true
}

func (idMapFunctions) Split(r idMapRange, val uint32, split uint32) (uint32, uint32) {
	return val, val + (split - r.Start)
}
