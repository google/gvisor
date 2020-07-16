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
	"net"
	"os/exec"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Machine describes a real machine for use in benchmarks.
type Machine interface {
	// GetContainer gets a container from the machine,
	GetContainer(ctx context.Context, log testutil.Logger) *dockerutil.Container

	// RunCommand runs cmd on this machine.
	RunCommand(cmd string, args ...string) (string, error)

	// Returns IP Address for the machine.
	IPAddress() (net.IP, error)

	// CleanUp cleans up this machine.
	CleanUp()
}

// localMachine describes this machine.
type localMachine struct {
}

// GetContainer implements Machine.GetContainer for localMachine.
func (l *localMachine) GetContainer(ctx context.Context, logger testutil.Logger) *dockerutil.Container {
	return dockerutil.MakeContainer(ctx, logger)
}

// RunCommand implements Machine.RunCommand for localMachine.
func (l *localMachine) RunCommand(cmd string, args ...string) (string, error) {
	c := exec.Command(cmd, args...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// IPAddress implements Machine.IPAddress.
func (l *localMachine) IPAddress() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP, nil
}

// CleanUp implements Machine.CleanUp and does nothing for localMachine.
func (*localMachine) CleanUp() {
}
