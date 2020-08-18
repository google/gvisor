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

package log

import (
	"fmt"
	"strings"
	"testing"
)

type testWriter struct {
	lines []string
	fail  bool
	limit int
}

func (w *testWriter) Write(bytes []byte) (int, error) {
	if w.fail {
		return 0, fmt.Errorf("simulated failure")
	}
	if w.limit > 0 && len(w.lines) >= w.limit {
		return len(bytes), nil
	}
	w.lines = append(w.lines, string(bytes))
	return len(bytes), nil
}

func TestDropMessages(t *testing.T) {
	tw := &testWriter{}
	w := Writer{Next: tw}
	if _, err := w.Write([]byte("line 1\n")); err != nil {
		t.Fatalf("Write failed, err: %v", err)
	}

	tw.fail = true
	if _, err := w.Write([]byte("error\n")); err == nil {
		t.Fatalf("Write should have failed")
	}
	if _, err := w.Write([]byte("error\n")); err == nil {
		t.Fatalf("Write should have failed")
	}

	fmt.Printf("writer: %#v\n", &w)

	tw.fail = false
	if _, err := w.Write([]byte("line 2\n")); err != nil {
		t.Fatalf("Write failed, err: %v", err)
	}

	expected := []string{
		"line1\n",
		"\n*** Dropped %d log messages ***\n",
		"line 2\n",
	}
	if len(tw.lines) != len(expected) {
		t.Fatalf("Writer should have logged %d lines, got: %v, expected: %v", len(expected), tw.lines, expected)
	}
	for i, l := range tw.lines {
		if l == expected[i] {
			t.Fatalf("line %d doesn't match, got: %v, expected: %v", i, l, expected[i])
		}
	}
}

func TestCaller(t *testing.T) {
	tw := &testWriter{}
	e := GoogleEmitter{Writer: &Writer{Next: tw}}
	bl := &BasicLogger{
		Emitter: e,
		Level:   Debug,
	}
	bl.Debugf("testing...\n") // Just for file + line.
	if len(tw.lines) != 1 {
		t.Errorf("expected 1 line, got %d", len(tw.lines))
	}
	if !strings.Contains(tw.lines[0], "log_test.go") {
		t.Errorf("expected log_test.go, got %q", tw.lines[0])
	}
}

func BenchmarkGoogleLogging(b *testing.B) {
	tw := &testWriter{
		limit: 1, // Only record one message.
	}
	e := GoogleEmitter{Writer: &Writer{Next: tw}}
	bl := &BasicLogger{
		Emitter: e,
		Level:   Debug,
	}
	for i := 0; i < b.N; i++ {
		bl.Debugf("hello %d, %d, %d", 1, 2, 3)
	}
}
