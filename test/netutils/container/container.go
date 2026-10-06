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

// Package container provides host-side setup for network test runners.
package container

import (
	"context"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/netutils"
)

// Setup starts the container with runner copied into /runner and exchanges IP
// addresses before returning. Setup, log collection and removal each receive
// their own timeout; callers must create a separate context for test traffic.
func Setup(t *testing.T, timeout time.Duration, opts dockerutil.RunOpts, runner string, ipv6 bool, port int, args ...string) (*dockerutil.Container, net.IP) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	d := dockerutil.MakeContainer(ctx, t)
	// Testing cancels t.Context before cleanup. Give logging and removal
	// independent deadlines so a log retrieval timeout does not prevent removal.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), timeout)
		defer cancel()
		d.CleanUp(ctx)
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), timeout)
		defer cancel()
		if logs, err := d.Logs(ctx); err != nil {
			log.Infof("Failed to retrieve container logs: %v", err)
		} else {
			log.Infof("=== Container logs: ===\n%s", logs)
		}
	})

	d.CopyFiles(&opts, "/runner", runner)
	if err := d.Spawn(ctx, opts, args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	ip, err := d.FindIP(ctx, ipv6)
	if err != nil {
		if ipv6 && err == dockerutil.ErrNoIP {
			t.Skip("No ipv6 address is available.")
		}
		t.Fatalf("failed to get container IP: %v", err)
	}

	// The runner learns our IP from the connection's source address;
	// ConnectTCP closes the connection without sending a payload.
	if err := netutils.ConnectTCP(ctx, ip, port, ipv6); err != nil {
		t.Fatalf("failed to send IP to container: %v", err)
	}
	return d, ip
}
