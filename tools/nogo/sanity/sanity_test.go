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

package sanity_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/runsc/flag"
)

func TestFormatFinding(t *testing.T) {
	args := flag.CommandLine.Args()
	if len(args) == 0 {
		t.Fatal("missing Nogo test command")
	}
	cmd := exec.CommandContext(t.Context(), args[0], args[1:]...)
	// Bazel runs the Nogo test from the main workspace's runfiles directory.
	cmd.Dir = filepath.Join(os.Getenv("TEST_SRCDIR"), os.Getenv("TEST_WORKSPACE"))
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("%v: got %v, want exit status 1; stdout:\n%s", cmd.Args, err, out)
	}
	const want = `fmt.Fprintf format %d has arg "hello world!" of wrong type string`
	if !bytes.Contains(out, []byte(want)) {
		t.Errorf("missing %q in stdout:\n%s", want, out)
	}
}
