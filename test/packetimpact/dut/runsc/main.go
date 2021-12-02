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

//go:build linux
// +build linux

// The runsc binary is used to bring up a gVisor DUT.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	"gvisor.dev/gvisor/test/packetimpact/dut/linux"
	"gvisor.dev/gvisor/test/packetimpact/internal/testing"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

type runsc struct {
	dut.Ifaces
	containerID      string
	runscPath        string
	runscLogsPath    string
	bundleDir        string
	rootDir          string
	cleanupRootDir   func()
	cleanupBundleDir func()
}

var _ dut.DUT = (*runsc)(nil)

func main() {
	ifaces, err := dut.Init(flag.CommandLine)
	if err != nil {
		log.Fatal(err)
	}
	// Find the path to the binaries.
	posixServerPath, err := testutil.FindFile(linux.PosixServerPath)
	if err != nil {
		log.Fatalf("failed to find posix_server binary: %s", err)
	}
	runscPath, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		log.Fatalf("failed to find runsc binary: %s", err)
	}

	// Create the OCI spec for the container with posix_server as the entrypoint.
	spec := testutil.NewSpecWithArgs(posixServerPath, "--ip", "0.0.0.0", "--port", strconv.FormatUint(dut.PosixServerPort, 10))
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get the current working directory: %s", err)
	}
	spec.Process.Cwd = pwd
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}

	// Use the DUT namespace which is the current namespace's.
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{
		Type: "network",
		Path: fmt.Sprintf("/proc/%d/ns/net", os.Getpid()),
	})

	// Prepare logs.
	runscLogPath, err := testing.UndeclaredOutput("runsc.%%TIMESTAMP%%.%%COMMAND%%.log")
	if err != nil {
		log.Fatalf("failed to create runsc log file: %s", err)
	}

	// Build the command to start runsc container.
	bundleDir, cleanupBundleDir, err := testutil.SetupBundleDir(spec)
	if err != nil {
		log.Fatalf("failed to create bundle dir: %s", err)
	}
	rootDir, cleanupRootDir, err := testutil.SetupRootDir()
	if err != nil {
		cleanupBundleDir()
		log.Fatalf("SetupRootDir failed: %v", err)
	}
	if err := dut.Run(&runsc{
		Ifaces:           ifaces,
		containerID:      testutil.RandomContainerID(),
		runscPath:        runscPath,
		runscLogsPath:    runscLogPath,
		bundleDir:        bundleDir,
		rootDir:          rootDir,
		cleanupRootDir:   cleanupRootDir,
		cleanupBundleDir: cleanupBundleDir,
	}); err != nil {
		log.Fatal(err)
	}
}

// Bootstrap implements dut.DUT.
func (r *runsc) Bootstrap(ctx context.Context) (testbench.DUTInfo, func() error, error) {
	// runsc will flush the addresses so we collect the info before we start it.
	info, err := linux.DUTInfo(r.Ifaces)
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to collect information about the DUT: %w", err)
	}

	// Start posix_server inside a runsc container.
	cmd := exec.CommandContext(
		ctx,
		r.runscPath,
		"-root", r.rootDir,
		"-network=sandbox",
		"-debug",
		"-debug-log", r.runscLogsPath,
		"-log-format=text",
		"-TESTONLY-unsafe-nonroot=true",
		"-net-raw=true",
		fmt.Sprintf("-panic-signal=%d", unix.SIGTERM),
		"-watchdog-action=panic",
		"run",
		"-bundle", r.bundleDir,
		r.containerID,
	)
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

	// runsc will keep using the assigned ip and mac addresses, but the device
	// id could have changed, we need to figure it out.
	remoteDevID, err := r.remoteDevID()
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to get test dev id: %w", err)
	}
	info.Net.RemoteDevID = remoteDevID
	return info, cmd.Wait, nil
}

// Cleanup implements dut.DUT.
func (r *runsc) Cleanup() {
	r.cleanupRootDir()
	r.cleanupBundleDir()
}

// remoteDevID gets the id of the test interface inside the runsc container.
func (r *runsc) remoteDevID() (uint32, error) {
	runscDevIDPath, err := testutil.FindFile("test/packetimpact/dut/runsc/devid")
	if err != nil {
		return 0, fmt.Errorf("failed to find binary runsc_devid: %w", err)
	}
	cmd := exec.Command(
		r.runscPath,
		"-root",
		r.rootDir,
		"-TESTONLY-unsafe-nonroot=true",
		"exec",
		r.containerID,
		runscDevIDPath,
		r.Ifaces.Test,
	)
	bytes, err := cmd.CombinedOutput()
	output := string(bytes)
	if err != nil {
		return 0, fmt.Errorf("failed to get the remote device id: %w, output: %s", err, output)
	}
	id, err := strconv.ParseUint(output, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s is not a number: %w", output, err)
	}
	return uint32(id), nil
}
