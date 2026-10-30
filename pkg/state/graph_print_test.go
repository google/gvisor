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
	"io"
	"strings"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/state/wire"
)

type printSliceHolder struct {
	full []int
	part []int
}

func (*printSliceHolder) StateTypeName() string { return "state.printSliceHolder" }
func (*printSliceHolder) StateFields() []string { return []string{"full", "part"} }
func (x *printSliceHolder) StateSave(s Sink) {
	s.graph.save(0, &x.full)
	s.graph.save(1, &x.part)
}
func (x *printSliceHolder) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.full)
	s.graph.load(1, &x.part)
}

type printMapHolder struct {
	m map[int]string
}

func (*printMapHolder) StateTypeName() string { return "state.printMapHolder" }
func (*printMapHolder) StateFields() []string { return []string{"m"} }
func (x *printMapHolder) StateSave(s Sink)    { s.graph.save(0, &x.m) }
func (x *printMapHolder) StateLoad(_ context.Context, s Source) {
	s.graph.load(0, &x.m)
}

type printCyclicInlineMap map[int]printCyclicInlineMap

type printCustomInlineMapHolder struct {
	inline map[int]string
	cyclic printCyclicInlineMap
}

func (*printCustomInlineMapHolder) StateTypeName() string { return "state.printCustomInlineMapHolder" }
func (*printCustomInlineMapHolder) StateFields() []string { return []string{"inline"} }
func (x *printCustomInlineMapHolder) StateSave(s Sink) {
	v := x.inline[1]
	s.SaveString(0, &v)
}
func (x *printCustomInlineMapHolder) StateLoad(_ context.Context, s Source) {
	var v string
	s.LoadString(0, &v)
	x.inline = map[int]string{1: v}
	x.cyclic = make(printCyclicInlineMap)
	x.cyclic[7] = x.cyclic
}

var registerPrintTestTypes = sync.OnceFunc(func() {
	Register((*printSliceHolder)(nil))
	Register((*printMapHolder)(nil))
	RegisterStruct((*printCustomInlineMapHolder)(nil))
	fingerprint.Store(0)
})

func encodeRawGraph(t *testing.T, root any) []byte {
	t.Helper()
	registerPrintTestTypes()
	var buf bytes.Buffer
	if _, err := saveGraph(context.Background(), &buf, root); err != nil {
		t.Fatalf("saveGraph: %v", err)
	}
	r := wire.Reader{Reader: bytes.NewReader(buf.Bytes())}
	hdr, err := ReadHeaderMode(&r)
	if err != nil {
		t.Fatalf("ReadHeaderMode: %v", err)
	}
	raw := make([]byte, hdr.Length)
	if _, err := io.ReadFull(r.Reader, raw); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	return raw
}

func TestPrintGraphSliceNotation(t *testing.T) {
	backing := make([]int, 2, 8)
	backing[0], backing[1] = 10, 20
	x := printSliceHolder{
		full: []int{1, 2, 3, 4},
		part: backing,
	}
	raw := encodeRawGraph(t, &x)
	var out strings.Builder
	if err := PrintGraph(&out, raw, 0, false); err != nil {
		t.Fatalf("PrintGraph: %v", err)
	}
	got := out.String()
	for _, want := range []string{"full: g0r1[:4:4]", "part: g0r2[:2:8]"} {
		if !strings.Contains(got, want) {
			t.Errorf("PrintGraph output missing %q:\n%s", want, got)
		}
	}
}

func TestPrintGraphDeterministic(t *testing.T) {
	x := printMapHolder{m: make(map[int]string)}
	for i := 0; i < 32; i++ {
		x.m[i] = strings.Repeat("x", i%5+1)
	}
	raw := encodeRawGraph(t, &x)

	for _, asHTML := range []bool{false, true} {
		var first strings.Builder
		if err := PrintGraph(&first, raw, 0, asHTML); err != nil {
			t.Fatalf("PrintGraph(html=%v): %v", asHTML, err)
		}
		want := first.String()
		for run := 1; run < 10; run++ {
			var next strings.Builder
			if err := PrintGraph(&next, raw, 0, asHTML); err != nil {
				t.Fatalf("PrintGraph(html=%v) run %d: %v", asHTML, run, err)
			}
			if got := next.String(); got != want {
				t.Fatalf("PrintGraph(html=%v) differed on run %d:\ngot:\n%s\nwant:\n%s", asHTML, run, got, want)
			}
		}
	}
}

func TestPrintGraphUnexportedInlineMapAndTrailingData(t *testing.T) {
	registerPrintTestTypes()
	x := printCustomInlineMapHolder{inline: map[int]string{1: "hello"}}
	raw := encodeRawGraph(t, &x)
	for _, asHTML := range []bool{false, true} {
		var out strings.Builder
		if err := PrintGraph(&out, raw, 0, asHTML); err != nil {
			t.Fatalf("PrintGraph(html=%v) on unexported inline map: %v", asHTML, err)
		}
		if !strings.Contains(out.String(), "hello") {
			t.Errorf("PrintGraph(html=%v) output missing inline map value:\n%s", asHTML, out.String())
		}
		if !strings.Contains(out.String(), "printCyclicInlineMap{...}") {
			t.Errorf("PrintGraph(html=%v) output missing cyclic inline map marker:\n%s", asHTML, out.String())
		}
	}

	withTrailing := append(append([]byte(nil), raw...), 0xff)
	var out strings.Builder
	if err := PrintGraph(&out, withTrailing, 0, false); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("PrintGraph with trailing byte = %v, want trailing data error", err)
	}
}
