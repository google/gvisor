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
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

// buildPtrObject builds a benchmark object.
func buildPtrObject(n int) any {
	b := new(benchStruct)
	for i := 0; i < n; i++ {
		b = &benchStruct{B: b}
	}
	return b
}

// buildMapObject builds a benchmark object.
func buildMapObject(n int) any {
	b := new(benchStruct)
	m := make(map[int]*benchStruct)
	for i := 0; i < n; i++ {
		m[i] = b
	}
	return &m
}

// buildSliceObject builds a benchmark object.
func buildSliceObject(n int) any {
	b := new(benchStruct)
	s := make([]*benchStruct, 0, n)
	for i := 0; i < n; i++ {
		s = append(s, b)
	}
	return &s
}

// buildAdoptionObject controls whether the enclosing array is discovered before
// or after its children's save hooks. Pointer-array capture queues the children;
// one additional intermediary delays array discovery until those children save.
func buildAdoptionObject(n int, captured bool) *benchAdoption {
	values := make([]benchAdopted, n)
	pointers := make([]*benchAdopted, n)
	for i := range values {
		values[i].Value = int64(i + 1)
		pointers[i] = &values[i]
	}
	parent := &benchAdoptionParent{Values: values}
	if captured {
		parent = &benchAdoptionParent{Next: parent}
	}
	return &benchAdoption{Pointers: pointers, Parent: parent}
}

var allObjects = map[string]struct {
	New func(int) any
}{
	"ptr": {
		New: buildPtrObject,
	},
	"map": {
		New: buildMapObject,
	},
	"slice": {
		New: buildSliceObject,
	},
	"adopt_uncaptured": {
		New: func(n int) any { return buildAdoptionObject(n, false) },
	},
	"adopt_captured": {
		New: func(n int) any { return buildAdoptionObject(n, true) },
	},
}

func TestAdoptedCaptureStorage(t *testing.T) {
	for _, captured := range []bool{false, true} {
		t.Run(fmt.Sprintf("captured=%t", captured), func(t *testing.T) {
			graph := buildAdoptionObject(3, captured)
			var saves int
			for _, child := range graph.Pointers {
				child.saves = &saves
			}
			var encoded bytes.Buffer
			if _, err := state.Save(t.Context(), &encoded, graph); err != nil {
				t.Fatal(err)
			}
			if got, want := saves, len(graph.Pointers); got != want {
				t.Fatalf("save hooks = %d, want %d", got, want)
			}
			var loaded benchAdoption
			if _, err := state.Load(t.Context(), &encoded, &loaded); err != nil {
				t.Fatal(err)
			}
			parent := loaded.Parent
			if captured {
				parent = parent.Next
			}
			if got, want := len(parent.Values), len(graph.Pointers); got != want {
				t.Fatalf("array length = %d, want %d", got, want)
			}
			if got, want := len(loaded.Pointers), len(parent.Values); got != want {
				t.Fatalf("pointer count = %d, want %d", got, want)
			}
			for i, child := range loaded.Pointers {
				if got, want := child, &parent.Values[i]; got != want {
					t.Errorf("child %d = %p, want %p", i, got, want)
				}
				if got, want := child.Value, int64(i+1); got != want {
					t.Errorf("child %d value = %d, want %d", i, got, want)
				}
			}
		})
	}
}

// gobSave is a version of save using gob (no stats available).
func gobSave(_ context.Context, w io.Writer, v any) (_ state.Stats, err error) {
	enc := gob.NewEncoder(w)
	err = enc.Encode(v)
	return
}

// gobLoad is a version of load using gob (no stats available).
func gobLoad(_ context.Context, r io.Reader, v any) (_ state.Stats, err error) {
	dec := gob.NewDecoder(r)
	err = dec.Decode(v)
	return
}

var allAlgos = map[string]struct {
	Save   func(context.Context, io.Writer, any) (state.Stats, error)
	Load   func(context.Context, io.Reader, any) (state.Stats, error)
	MaxPtr int
}{
	"state": {
		Save: state.Save,
		Load: state.Load,
	},
	"gob": {
		Save: gobSave,
		Load: gobLoad,
	},
}

func BenchmarkEncoding(b *testing.B) {
	for objName, objInfo := range allObjects {
		for algoName, algoInfo := range allAlgos {
			b.Run(fmt.Sprintf("%s/%s", objName, algoName), func(b *testing.B) {
				v := objInfo.New(1024)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := algoInfo.Save(context.Background(), io.Discard, v); err != nil {
						b.Errorf("save failed: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkDecoding(b *testing.B) {
	for objName, objInfo := range allObjects {
		for algoName, algoInfo := range allAlgos {
			b.Run(fmt.Sprintf("%s/%s", objName, algoName), func(b *testing.B) {
				v := objInfo.New(1024)
				buf := new(bytes.Buffer)
				if _, err := algoInfo.Save(context.Background(), buf, v); err != nil {
					b.Errorf("save failed: %v", err)
				}
				b.ReportAllocs()
				var r bytes.Reader
				for b.Loop() {
					r.Reset(buf.Bytes())
					if _, err := algoInfo.Load(context.Background(), &r, v); err != nil {
						b.Errorf("load failed: %v", err)
					}
				}
			})
		}
	}
}

// benchGraphNodes is the number of nodes of the graphs of BenchmarkGraph.
const benchGraphNodes = 20000

// BenchmarkGraphSave saves a large random graph.
func BenchmarkGraphSave(b *testing.B) {
	root := randomGraph(1, graphOptions{nodes: benchGraphNodes, all: true})
	b.ReportAllocs()
	var n int
	for b.Loop() {
		w := countingWriter{}
		if _, err := state.Save(context.Background(), &w, root); err != nil {
			b.Fatalf("save failed: %v", err)
		}
		n = w.n
	}
	b.ReportMetric(float64(n), "encoded-B")
}

// BenchmarkGraphLoad loads a large random graph.
func BenchmarkGraphLoad(b *testing.B) {
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, randomGraph(1, graphOptions{nodes: benchGraphNodes, all: true})); err != nil {
		b.Fatalf("save failed: %v", err)
	}
	b.ReportAllocs()
	var r bytes.Reader
	for b.Loop() {
		r.Reset(buf.Bytes())
		var root gRoot
		if _, err := state.Load(context.Background(), &r, &root); err != nil {
			b.Fatalf("load failed: %v", err)
		}
	}
}

// countingWriter counts the bytes written to it.
type countingWriter struct {
	n int
}

// Write implements io.Writer.Write.
func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}
