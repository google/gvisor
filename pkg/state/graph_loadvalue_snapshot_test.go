// Copyright 2026 The gVisor Authors.
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

package state

import (
	"bytes"
	"context"
	"testing"
)

type loadValueSnapshot struct {
	number uint64
	copied uint64
	boxed  any
}

func (*loadValueSnapshot) StateTypeName() string { return "state.loadValueSnapshot" }
func (*loadValueSnapshot) StateFields() []string { return []string{"number"} }

func (x *loadValueSnapshot) StateSave(s Sink) {
	s.SaveValue(0, x.number)
}

func (x *loadValueSnapshot) StateLoad(_ context.Context, s Source) {
	s.LoadValue(0, &x.number, func(value any) {
		x.boxed = value
		x.copied = value.(uint64)
	})
}

func init() { RegisterStruct((*loadValueSnapshot)(nil)) }

func TestLoadValueSnapshot(t *testing.T) {
	originalMode := GraphEngineEnabled()
	t.Cleanup(func() { EnableGraphEngine(originalMode) })
	for _, tc := range []struct {
		name  string
		graph bool
	}{{"legacy", false}, {"graph", true}} {
		t.Run(tc.name, func(t *testing.T) {
			EnableGraphEngine(tc.graph)
			const saved, changed uint64 = 11, 22
			var buf bytes.Buffer
			if _, err := Save(t.Context(), &buf, &loadValueSnapshot{number: saved}); err != nil {
				t.Fatalf("Save: %v", err)
			}
			var got loadValueSnapshot
			if _, err := Load(t.Context(), &buf, &got); err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got.number != saved || got.copied != saved || got.boxed != saved {
				t.Fatalf("after Load: number=%d copied=%d boxed=%v, want %d for all three", got.number, got.copied, got.boxed, saved)
			}
			got.number = changed
			t.Logf("engine=%s field=%d copied=%d retained=%d", tc.name, got.number, got.copied, got.boxed)
			if got, want := got.boxed, any(saved); got != want {
				t.Errorf("callback value after mutating field = %v, want %v", got, want)
			}
		})
	}
}
