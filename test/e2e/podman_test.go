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

// Package integration provides end-to-end integration tests for runsc.
package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// podmanTestVariant defines a Podman configuration variant to test inside a gVisor container.
// We currently test only rootless Podman.
type podmanTestVariant struct {
	Name       string
	User       string
	WorkDir    string
	PodmanArgs []string
	Enabled    bool
	SkipReason string
}

// podmanTestVariants returns all Podman integration test variants.
func podmanTestVariants() []podmanTestVariant {
	return []podmanTestVariant{
		{
			Name: "Rootful with host networking",
			User: "root",
			PodmanArgs: []string{
				"--network=host",
			},
			Enabled:    false,
			SkipReason: "Disabled: Rootful Podman attempts unsupported cgroupfs hierarchy writes inside gVisor",
		},
		{
			Name: "Rootful with default bridge networking",
			User: "root",
			PodmanArgs: []string{
				"--network=bridge",
			},
			Enabled:    false,
			SkipReason: "Network bridge and veth isolation currently unsupported with Podman under runsc",
		},
		{
			Name: "Rootful with none networking",
			User: "root",
			PodmanArgs: []string{
				"--network=none",
			},
			Enabled:    false,
			SkipReason: "Disabled: Rootful Podman attempts unsupported cgroupfs writes inside gVisor",
		},
		{
			Name:    "Rootless with host networking",
			User:    "nonroot",
			WorkDir: "/home/nonroot",
			PodmanArgs: []string{
				"--network=host",
			},
			Enabled: true,
		},
		{
			Name:    "Rootless with default networking",
			User:    "nonroot",
			WorkDir: "/home/nonroot",
			PodmanArgs: []string{
				"--network=bridge",
			},
			Enabled:    false,
			SkipReason: "rootless networking does not work for gvisor yet",
		},
	}
}

// run executes Podman inside a gVisor container created by MakeContainer.
func (test podmanTestVariant) run(ctx context.Context, logger testutil.Logger) (string, error) {
	d := dockerutil.MakeContainer(ctx, logger)
	defer d.CleanUp(ctx)
	opts := dockerutil.RunOpts{
		Image:      "basic/podmantest",
		User:       test.User,
		WorkDir:    test.WorkDir,
		Privileged: true,
	}
	if err := d.Spawn(ctx, opts, "sleep", "infinity"); err != nil {
		return "", fmt.Errorf("spawn failed: %v", err)
	}

	const wantMessage = "Hello from nested Podman inside gVisor!"
	args := []string{
		"podman",
		"run",
		"--rm",
	}
	args = append(args, test.PodmanArgs...)
	args = append(args, "alpine", "echo", wantMessage)

	logger.Logf("Running inside gVisor container: %v", args)
	got, err := d.Exec(ctx, dockerutil.ExecOpts{
		User:    test.User,
		WorkDir: test.WorkDir,
	}, args...)
	got = strings.TrimSpace(got)
	if err != nil {
		return got, fmt.Errorf("podman run failed: %v (output: %s)", err, got)
	}
	if !strings.Contains(got, wantMessage) {
		return got, fmt.Errorf("did not observe substring %q in logs: %s", wantMessage, got)
	}
	return got, nil
}

// TestPodmanInGVisor runs Podman inside a gVisor container.
func TestPodman(t *testing.T) {
	ctx := context.Background()
	for _, test := range podmanTestVariants() {
		t.Run(test.Name, func(t *testing.T) {
			if !test.Enabled {
				t.Skipf("Skipping disabled Podman test variant %q: %s", test.Name, test.SkipReason)
				return
			}
			if logs, err := test.run(ctx, t); err != nil {
				t.Fatalf("Error: %v; logs:\n%s", err, logs)
			}
		})
	}
}
