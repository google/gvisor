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

package sandbox

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

func TestSandboxProcessEnvPreservesTMPDIR(t *testing.T) {
	t.Setenv("TMPDIR", "/realtmp")
	t.Setenv("TMP", "/wrong-tmp")
	t.Setenv("TEMP", "/wrong-temp")

	env := sandboxProcessEnv(&config.Config{})
	if !envContains(env, "TMPDIR=/realtmp") {
		t.Fatalf("sandboxProcessEnv() = %v, missing TMPDIR", env)
	}
	if envHasPrefix(env, "TMP=") {
		t.Fatalf("sandboxProcessEnv() = %v, leaked TMP", env)
	}
	if envHasPrefix(env, "TEMP=") {
		t.Fatalf("sandboxProcessEnv() = %v, leaked TEMP", env)
	}
}

func TestSandboxProcessEnvLeavesTMPDIRUnset(t *testing.T) {
	t.Setenv("TMPDIR", "")

	env := sandboxProcessEnv(&config.Config{})
	if envHasPrefix(env, "TMPDIR=") {
		t.Fatalf("sandboxProcessEnv() = %v, unexpectedly set TMPDIR", env)
	}
}

func envContains(env []string, want string) bool {
	for _, got := range env {
		if got == want {
			return true
		}
	}
	return false
}

func envHasPrefix(env []string, prefix string) bool {
	for _, got := range env {
		if strings.HasPrefix(got, prefix) {
			return true
		}
	}
	return false
}
