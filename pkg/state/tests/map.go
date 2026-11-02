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

package tests

import (
	"context"
	"maps"

	"gvisor.dev/gvisor/pkg/state"
)

// +stateify savable
type mapContainer struct {
	v map[int]any
}

// +stateify savable
type mapPtrContainer struct {
	v *map[int]any
}

// +stateify savable
type registeredMapStruct struct{}

// +stateify type
type mapLoadHook struct {
	value int
}

type mapLoadHookContextKey struct{}

func (v *mapLoadHook) StateSave(sink state.Sink) {
	sink.Save(0, &v.value)
}

func (v *mapLoadHook) StateLoad(ctx context.Context, src state.Source) {
	var value int
	src.Load(0, &value)
	src.AfterLoad(func() {
		v.value = value
		ctx.Value(mapLoadHookContextKey{}).(func(*mapLoadHook))(v)
	})
}

// +stateify type
type mapLoadSnapshot struct {
	entries map[mapLoadHook]int
	inline  mapLoadHook
}

func (s *mapLoadSnapshot) StateSave(sink state.Sink) {
	sink.Save(0, &s.entries)
	sink.Save(1, &s.inline)
}

func (s *mapLoadSnapshot) StateLoad(_ context.Context, src state.Source) {
	var snapshot map[mapLoadHook]int
	var inline mapLoadHook
	src.AfterLoad(func() {
		s.entries = snapshot
		s.inline = inline
	})
	src.LoadValue(0, new(map[mapLoadHook]int), func(v any) {
		snapshot = maps.Clone(v.(map[mapLoadHook]int))
	})
	src.LoadValue(1, new(mapLoadHook), func(v any) {
		inline = v.(mapLoadHook)
	})
}
