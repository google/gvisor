// Copyright 2023 The gVisor Authors.
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

package dumpfilter_test

import (
	"os/exec"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestDumpFilter tests that the `dumpfilter` program works.
func TestDumpFilter(t *testing.T) {
	binPath, err := testutil.FindFile("runsc/boot/filter/dumpfilter/dumpfilter")
	if err != nil {
		t.Fatalf("cannot locate dumpfilter: %v", err)
	}
	output, err := exec.Command(binPath).CombinedOutput()
	for _, line := range strings.Split(string(output), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Errorf("program failed: %v", err)
	}
}
