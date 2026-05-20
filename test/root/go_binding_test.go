// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package go_binding_test

import (
	"context"
	"strings"
	"testing"

	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func TestExecDmesg(t *testing.T) {
	ctx := context.Background()

	// Create the background sandbox via subprocess
	sb, err := sandbox.New(ctx)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	// Execute dmesg in the gVisor sandbox.
	output, _, err := sb.Exec(ctx, "dmesg")
	if err != nil {
		t.Fatalf("failed to execute command in sandbox: %v", err)
	}

	if !strings.Contains(output, "Starting gVisor") {
		t.Errorf("Exec(\"dmesg\") =  %v; wanted: %v", output, "Starting gVisor")
	}
}

func TestSandboxOptions(t *testing.T) {
	ctx := context.Background()
	runtimeDir := t.TempDir()
	id := "iwillbeasandbox"

	sb, err := sandbox.New(ctx, sandbox.WithID(id), sandbox.WithRuntimeDir(runtimeDir))
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	defer func() {
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("failed to clean up sandbox: %v", err)
		}
	}()

	if got := sb.Bundle(); !strings.HasPrefix(got, runtimeDir) {
		t.Errorf("sb.Bundle() = %v; want prefix %v", got, runtimeDir)
	}
}
