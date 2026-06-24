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

package cmd

import (
	"testing"

	"gvisor.dev/gvisor/runsc/flag"
)

func TestReadFlags(t *testing.T) {
	r := Read{}
	f := flag.NewFlagSet("read", flag.ContinueOnError)
	r.SetFlags(f)

	if err := f.Parse([]string{"--size", "4096"}); err != nil {
		t.Fatalf("f.Parse failed: %v", err)
	}
	if r.size != 4096 {
		t.Errorf("expected size 4096, got %d", r.size)
	}
}
