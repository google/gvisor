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

// Package syncevent provides efficient primitives for goroutine
// synchronization based on event bitmasks.
package syncevent

// Set is a bitmask where each bit represents a distinct user-defined event.
// The event package does not treat any bits in Set specially.
type Set uint64

const (
	// NoEvents is a Set containing no events.
	NoEvents = Set(0)

	// AllEvents is a Set containing all possible events.
	AllEvents = ^Set(0)

	// MaxEvents is the number of distinct events that can be represented by a Set.
	MaxEvents = 64
)
