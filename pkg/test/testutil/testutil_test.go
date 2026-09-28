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

package testutil

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestWaitUntilRead(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantErr     bool
	}{
		{name: "match", input: "first\ncontains wanted text\n"},
		{name: "EOF", input: "other text\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := WaitUntilRead(strings.NewReader(tc.input), "wanted", time.Second); (err != nil) != tc.wantErr {
				t.Fatalf("WaitUntilRead(%q) = %v, want error: %t", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestWaitUntilReadTimeout(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	// No data can arrive before this immediate timeout. The caller still owns
	// releasing the pipe; scanner completion is covered separately below.
	if err := WaitUntilRead(r, "wanted", 0); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("WaitUntilRead() = %v, want timeout", err)
	}
}

func TestReadUntilCanceled(t *testing.T) {
	for _, tc := range []struct {
		name, lateInput string
	}{
		{name: "match", lateInput: "wanted\n"},
		{name: "EOF"},
		{name: "other_line", lateInput: "other text\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			cancel := make(chan struct{})
			result := readUntil(r, "wanted", cancel)
			close(cancel)
			if tc.lateInput != "" {
				if _, err := io.WriteString(w, tc.lateInput); err != nil {
					t.Fatalf("writing late input: %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("closing writer: %v", err)
			}
			// The producer closes result after all scanner work, so draining it
			// joins that work rather than merely acknowledging a pipe Read.
			for range result {
			}
		})
	}
}
