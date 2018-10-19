// Copyright 2018 Google LLC
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
	"testing"
)

type testWriter struct {
	lines []string
	fail  bool
}

func (w *testWriter) Write(bytes []byte) (int, error) {
	if w.fail {
		return 0, fmt.Errorf("simulated failure")
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

	fmt.Printf("writer: %+v\n", w)

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
