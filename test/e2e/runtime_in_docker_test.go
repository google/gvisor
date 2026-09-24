// Copyright 2024 The gVisor Authors.
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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// testVariant is a variant of the gVisor in Docker test.
type testVariant struct {
	Name          string
	User          string
	WorkDir       string
	CapAdd        []string
	Args          []string
	MountCgroupfs bool
}

// run runs the test variant.
func (test testVariant) run(ctx context.Context, logger testutil.Logger) (string, error) {
	runscPath, err := testutil.FindRunsc()
	if err != nil {
		return "", fmt.Errorf("cannot locate runsc binary: %v", err)
	}
	gvisorBinDir, err := testutil.FindFile("release/gvisor-bin")
	if err != nil {
		return "", fmt.Errorf("cannot locate gvisor-bin directory: %v", err)
	}
	runscRealPath, err := filepath.EvalSymlinks(runscPath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve runsc path %q: %v", runscPath, err)
	}
	gvisorBinEntries, err := os.ReadDir(gvisorBinDir)
	if err != nil {
		return "", fmt.Errorf("cannot read gvisor-bin directory %q: %v", gvisorBinDir, err)
	}
	var sidecarMounts []mount.Mount
	for _, entry := range gvisorBinEntries {
		src := filepath.Join(gvisorBinDir, entry.Name())
		realPath, err := filepath.EvalSymlinks(src)
		if err != nil {
			return "", fmt.Errorf("cannot resolve sidecar path %q: %v", src, err)
		}
		sidecarMounts = append(sidecarMounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   realPath,
			Target:   "/gvisor-bin/" + entry.Name(),
			ReadOnly: true,
		})
	}
	d := dockerutil.MakeNativeContainer(ctx, logger)
	defer d.CleanUp(ctx)
	opts := dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		User:    test.User,
		WorkDir: test.WorkDir,
		SecurityOpts: []string{
			// Disable default seccomp filter which blocks `mount(2)` and others.
			"seccomp=unconfined",

			// Disable AppArmor which also blocks mounts.
			"apparmor=unconfined",

			// Set correct SELinux label; this allows ptrace.
			"label=type:container_engine_t",
		},
		CapAdd: test.CapAdd,
		Mounts: append([]mount.Mount{
			// Mount the runtime binary.
			{
				Type:     mount.TypeBind,
				Source:   runscRealPath,
				Target:   "/runtime",
				ReadOnly: true,
			},
		}, sidecarMounts...),
	}
	if test.MountCgroupfs {
		opts.Mounts = append(opts.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   "/sys/fs/cgroup",
			Target:   "/sys/fs/cgroup",
			ReadOnly: false,
		})
	}
	const wantMessage = "It became a jumble of words, a litany, almost a kind of glossolalia."
	args := []string{
		"/runtime",
		"--debug=true",
		"--debug-log=/dev/stderr",
	}
	args = append(args, test.Args...)
	args = append(args, "do")
	// Split the message into separate substrings to avoid matching on the message
	// just because the sandbox argv in the debug logs matches it
	// (we want to match stdout specifically).
	splitWantMessage := strings.Split(wantMessage, " ")
	var command []string
	for _, arg := range splitWantMessage {
		command = append(command, fmt.Sprintf("printf '%%s ' %q", arg))
	}
	args = append(args, "/bin/sh", "-c", strings.Join(command, " && "))
	logger.Logf("Running: %v", args)
	got, err := d.Run(ctx, opts, args...)
	got = strings.TrimSpace(got)
	if err != nil {
		return got, err
	}
	if !strings.Contains(got, wantMessage) {
		return got, fmt.Errorf("did not observe substring %q in logs", wantMessage)
	}
	return got, nil
}

// failureCases returns modified versions of this same test that are expected
// to fail. Verifying that these variants fail ensures that each test variant
// runs with the minimal amount of deviations from the default configuration.
func (test testVariant) failureCases() []testVariant {
	failureCase := func(name string) testVariant {
		copy := test
		copy.Name = name
		return copy
	}
	var failureCases []testVariant
	if test.MountCgroupfs {
		copy := failureCase("without cgroupfs mounted")
		copy.MountCgroupfs = false
		failureCases = append(failureCases, copy)
	}
	for i, capAdd := range test.CapAdd {
		copy := failureCase(fmt.Sprintf("without capability %s", capAdd))
		copy.CapAdd = append(append([]string(nil), test.CapAdd[:i]...), test.CapAdd[i+1:]...)
		failureCases = append(failureCases, copy)
	}
	for _, tryRemoveArg := range []string{
		"--rootless=true",
		"--ignore-cgroups=true",
	} {
		if index := slices.Index(test.Args, tryRemoveArg); index != -1 {
			copy := failureCase(fmt.Sprintf("without argument %s", tryRemoveArg))
			copy.Args = append(append([]string(nil), test.Args[:index]...), test.Args[index+1:]...)
			failureCases = append(failureCases, copy)
		}
	}
	return failureCases
}

// TestGVisorInDocker runs `runsc` inside a non-gVisor container.
// This is used in contexts such as Dangerzone:
// https://gvisor.dev/blog/2024/09/23/safe-ride-into-the-dangerzone/
func TestGVisorInDocker(t *testing.T) {
	ctx := context.Background()
	for _, test := range []testVariant{
		{
			Name: "Rootful",
			User: "root",
			CapAdd: []string{
				// Necessary to set up networking (creating veth devices).
				"NET_ADMIN",
				// Necessary to set up networking, which calls `ip netns add` which
				// calls `mount(2)`.
				"SYS_ADMIN",
			},
			// Mount cgroupfs as writable, otherwise the runtime won't be able to
			// set up cgroups.
			MountCgroupfs: true,
		},
		{
			Name: "Rootful without networking",
			User: "root",
			CapAdd: []string{
				// "Can't run sandbox process in minimal chroot since we don't have CAP_SYS_ADMIN"
				"SYS_ADMIN",
			},
			Args: []string{
				"--network=none",
			},
			MountCgroupfs: true,
		},
		{
			Name: "Rootful with host networking",
			User: "root",
			CapAdd: []string{
				// Necessary to set up networking (creating veth devices).
				"NET_ADMIN",
				// Necessary to set up networking, which calls `ip netns add` which
				// calls `mount(2)`.
				"SYS_ADMIN",
			},
			Args: []string{
				"--network=host",
			},
			MountCgroupfs: true,
		},
		{
			Name: "Rootful without networking and cgroupfs",
			User: "root",
			CapAdd: []string{
				// "Can't run sandbox process in minimal chroot since we don't have CAP_SYS_ADMIN"
				"SYS_ADMIN",
			},
			Args: []string{
				"--network=none",
				"--ignore-cgroups=true",
			},
		},
		{
			Name:    "Rootless",
			User:    "nonroot",
			WorkDir: "/home/nonroot",
			Args: []string{
				"--rootless=true",
			},
		},
		{
			Name:    "Rootless without networking",
			User:    "nonroot",
			WorkDir: "/home/nonroot",
			Args: []string{
				"--rootless=true",
				"--network=none",
			},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			if logs, err := test.run(ctx, t); err != nil {
				t.Fatalf("Error: %v; logs:\n%s", err, logs)
			}
			for _, failureCase := range test.failureCases() {
				t.Run(failureCase.Name, func(t *testing.T) {
					if logs, err := failureCase.run(ctx, t); err == nil {
						t.Fatalf("Failure case unexpectedly succeeded; logs:\n%s", logs)
					}
				})
			}
		})
	}
}
