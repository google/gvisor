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

// Package mobyutil provides shared helpers for Moby integration tests and benchmarks.
package mobyutil

import (
	"context"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// DockerInGvisorCapabilities returns the Linux capabilities required to run
// dockerd inside a gVisor sandbox.
func DockerInGvisorCapabilities() []string {
	return []string{
		"audit_write",
		"chown",
		"dac_override",
		"fowner",
		"fsetid",
		"kill",
		"mknod",
		"net_admin",
		"net_bind_service",
		"net_raw",
		"setfcap",
		"setgid",
		"setpcap",
		"setuid",
		"sys_admin",
		"sys_chroot",
		"sys_ptrace",
	}
}

// StartContainer spawns a moby container with dockerd running on tmpfs and
// waits until the inner daemon is ready.
func StartContainer(ctx context.Context, logger testutil.Logger, machine harness.Machine) (*dockerutil.Container, error) {
	isGVisor, err := dockerutil.IsGVisorRuntime(ctx)
	if err != nil {
		return nil, fmt.Errorf("IsGVisorRuntime failed: %w", err)
	}

	d := machine.GetContainer(ctx, logger)
	opts := dockerutil.RunOpts{
		Image:      "moby",
		Privileged: !isGVisor,
		CapAdd:     DockerInGvisorCapabilities(),
	}
	startScript := "mount -t tmpfs tmpfs /tmp && mkdir -p /tmp/docker-data && exec dockerd --data-root /tmp/docker-data -b none -D"
	if err := d.Spawn(ctx, opts, "sh", "-c", startScript); err != nil {
		d.CleanUp(ctx)
		return nil, fmt.Errorf("failed to spawn moby container: %w", err)
	}

	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := testutil.PollContext(pollCtx, func() error {
		_, err := d.Exec(pollCtx, dockerutil.ExecOpts{}, "docker", "info")
		return err
	}); err != nil {
		logs, _ := d.Logs(ctx)
		d.CleanUp(ctx)
		return nil, fmt.Errorf("timeout waiting for dockerd: %w\n%s", err, logs)
	}
	return d, nil
}
