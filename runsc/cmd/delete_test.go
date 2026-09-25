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

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
)

func TestNotFound(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Parse([]string{"123"})
	dir, err := os.MkdirTemp("", "metadata")
	if err != nil {
		t.Fatalf("error creating dir: %v", err)
	}
	conf := &config.Config{RootDir: dir}

	d := Delete{}
	if err := d.execute(f, conf); err == nil {
		t.Error("Deleting non-existent container should have failed")
	}

	d = Delete{force: true}
	if err := d.execute(f, conf); err != nil {
		t.Errorf("Deleting non-existent container with --force should NOT have failed: %v", err)
	}
}

// writeStateFile writes a state file for a container of the given sandbox, so
// that container.LoadSandbox() finds it.
func writeStateFile(t *testing.T, rootDir, sbID, cid string, status container.Status) {
	t.Helper()
	path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", cid, sbID))
	state := fmt.Sprintf(`{"id":%q,"status":%q,"sandbox":{"id":%q,"noRootContainer":true}}`, cid, status, sbID)
	if err := os.WriteFile(path, []byte(state), 0644); err != nil {
		t.Fatalf("error writing state file %q: %v", path, err)
	}
}

// TestDeleteRunningRequiresForce checks that deleting a running container
// needs --force, except for a sandbox with no containers running. See
// requireForce.
func TestDeleteRunningRequiresForce(t *testing.T) {
	for _, tc := range []struct {
		name            string
		noRootContainer bool
		// subcontainers holds the status of each container in the sandbox.
		subcontainers []container.Status
		wantErr       bool
	}{
		{name: "regular container", wantErr: true},
		{name: "empty sandbox", noRootContainer: true},
		{name: "created container", noRootContainer: true, subcontainers: []container.Status{container.Created}},
		{name: "stopped container", noRootContainer: true, subcontainers: []container.Status{container.Stopped}},
		{name: "paused container", noRootContainer: true, subcontainers: []container.Status{container.Stopped, container.Paused}, wantErr: true},
		// No sandbox process backs these state files, so the refresh marks the
		// container stopped.
		{name: "stale running container", noRootContainer: true, subcontainers: []container.Status{container.Running}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			conf := &config.Config{RootDir: rootDir}
			const sbID = "sandbox"
			writeStateFile(t, rootDir, sbID, sbID, container.Running)
			for i, status := range tc.subcontainers {
				writeStateFile(t, rootDir, sbID, fmt.Sprintf("cont%d", i), status)
			}

			c := &container.Container{
				ID:     sbID,
				Status: container.Running,
				Sandbox: &sandbox.Sandbox{
					ID:              sbID,
					NoRootContainer: tc.noRootContainer,
				},
			}
			err := requireForce(conf, c)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("requireForce() = %v, wantErr: %t", err, tc.wantErr)
			}
		})
	}
}
