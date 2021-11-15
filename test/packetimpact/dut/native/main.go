// Copyright 2021 The gVisor Authors.
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

//go:build linux && go1.10
// +build linux,go1.10

// The native binary is used to bring up a native linux DUT.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	"gvisor.dev/gvisor/test/packetimpact/dut/linux"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

var _ dut.DUT = (*native)(nil)

type native struct {
	dut.Ifaces
}

func main() {
	ifaces, err := dut.Init()
	if err != nil {
		log.Fatal(err)
	}
	if err := dut.Run(&native{
		Ifaces: ifaces,
	}); err != nil {
		log.Fatal(err)
	}
}

// Bootstrap implements dut.DUT.
func (n *native) Bootstrap(ctx context.Context) (testbench.DUTInfo, func() error, error) {
	// Enable ICMP sockets.
	if err := os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 0"), 0); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to enable icmp sockets: %w", err)
	}

	// Find the posix_server binary.
	path, err := testutil.FindFile(linux.PosixServerPath)
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to find the posix_server binary: %w", err)
	}

	// Start the process.
	cmd := exec.CommandContext(ctx, path, "--ip", "0.0.0.0", "--port", strconv.FormatUint(dut.PosixServerPort, 10))
	cmd.SysProcAttr = &unix.SysProcAttr{
		Pdeathsig: unix.SIGKILL,
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to create stderr pipe to the posix server process: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to start the posix server process: %w", err)
	}
	if err := dut.WaitForServer(errPipe); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to wait for the server to listen: %w", err)
	}

	// Collect DUT information.
	info, err := linux.DUTInfo(n.Ifaces)
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to collect information about the DUT: %w", err)
	}
	return info, cmd.Wait, nil
}

// Bootstrap implements dut.DUT
func (*native) Cleanup() {
	// For a native DUT case, we only need to cleanup the posix_server process which we set up to
	// deliver a SIGKILL signal whenever we exit, so there is nothing to do here.
}
