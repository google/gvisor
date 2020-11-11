// Copyright 2020 The gVisor Authors.
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

package harness

import (
	"context"
	"fmt"
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

//TODO(gvisor.dev/issue/3535): move to own package or move methods to harness struct.

// WaitUntilServing grabs a container from `machine` and waits for a server at
// IP:port.
func WaitUntilServing(ctx context.Context, machine Machine, server net.IP, port int) error {
	var logger testutil.DefaultLogger = "util"
	netcat := machine.GetNativeContainer(ctx, logger)
	defer netcat.CleanUp(ctx)

	cmd := fmt.Sprintf("while ! wget -q --spider http://%s:%d; do true; done", server, port)
	_, err := netcat.Run(ctx, dockerutil.RunOpts{
		Image: "benchmarks/util",
	}, "sh", "-c", cmd)
	return err
}

// DropCaches drops caches on the provided machine. Requires root.
func DropCaches(machine Machine) error {
	if out, err := machine.RunCommand("/bin/sh", "-c", "sync && sysctl vm.drop_caches=3"); err != nil {
		return fmt.Errorf("failed to drop caches: %v logs: %s", err, out)
	}
	return nil
}

// DebugLog prints debug messages if the debug flag is set.
func DebugLog(b *testing.B, msg string, args ...interface{}) {
	b.Helper()
	if *debug {
		b.Logf(msg, args...)
	}
}
