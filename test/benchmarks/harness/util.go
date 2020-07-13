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

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// WaitUntilServing grabs a container from `machine` and waits for a server at
// IP:port.
func WaitUntilServing(ctx context.Context, machine Machine, server net.IP, port int) error {
	var logger testutil.DefaultLogger = "netcat"
	netcat := machine.GetContainer(ctx, logger)
	defer netcat.CleanUp(ctx)

	cmd := fmt.Sprintf("while ! nc -zv %s %d; do true; done", server.String(), port)
	_, err := netcat.Run(ctx, dockerutil.RunOpts{
		Image: "packetdrill",
	}, "sh", "-c", cmd)
	return err
}
