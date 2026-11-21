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

package main

import (
	"os/exec"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestVersion(t *testing.T) {
	runsc, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(runsc, "--version").Output()
	if err != nil {
		t.Fatalf("runsc --version: %v", err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	value, ok := strings.CutPrefix(line, "runsc version ")
	if !ok || value == "" || value == "VERSION_MISSING" {
		t.Errorf("first line of runsc --version = %q, want a stamped runsc version", line)
	}
}
