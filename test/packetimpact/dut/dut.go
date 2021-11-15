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

// Package dut provides common definitions and utilities to be shared by DUTs.
package dut

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// completeFd is used for notifying the parent for the completion of setup.
	completeFd = 3
	// PosixServerPort is the port the posix server should listen on.
	PosixServerPort = 54321
)

// Ifaces describe the names of the interfaces on DUT.
type Ifaces struct {
	// Ctrl is the name of the control interface.
	Ctrl string
	// Test is the name of the test interface.
	Test string
}

// Init puts the current process into the target network namespace, the user of
// this library should call this function in the beginning.
func Init() (Ifaces, error) {
	// The DUT might create child processes, we don't want this fd to leak into
	// those processes as it keeps the pipe open and the testbench will hang
	// waiting for an EOF on the pipe.
	unix.CloseOnExec(completeFd)
	var ifaces Ifaces
	// Parse command line flags. It is effectively the same as using top-level
	// functions in flag package, but more explicit that we exit if the parsing
	// failed.
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&ifaces.Ctrl, "ctrl_iface", "", "the name of the control interface")
	fs.StringVar(&ifaces.Test, "test_iface", "", "the name of the test interface")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return Ifaces{}, err
	}
	return ifaces, nil
}

// DUT is an interface for different platforms of DUTs.
type DUT interface {
	// Bootstrap starts a DUT and returns the collected DUTInfo and a function
	// for the caller to call to wait for the completion of the DUT.
	Bootstrap(ctx context.Context) (testbench.DUTInfo, func() error, error)
	// Cleanup stops the DUT and cleans up the resources being used.
	Cleanup()
}

// Run is the provided function that calls dut's Bootstrap and Cleanup
// methods and returns the DUT information to the parent through the pipe.
func Run(dut DUT) error {
	defer dut.Cleanup()

	// Register for cleanup signals.
	stopSigs := make(chan os.Signal, 1)
	signal.Notify(stopSigs, unix.SIGTERM, unix.SIGINT)
	defer signal.Stop(stopSigs)

	// Start bootstrapping the DUT.
	g, ctx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g.Go(func() error {
		info, waitFn, err := dut.Bootstrap(ctx)
		if err != nil {
			return err
		}
		bytes, err := json.Marshal(info)
		if err != nil {
			return fmt.Errorf("failed to marshal DUT info into json: %w", err)
		}
		// Send the DUT information to the parent through the pipe.
		completeFile := os.NewFile(completeFd, "complete")
		for len(bytes) > 0 {
			n, err := completeFile.Write(bytes)
			if err != nil && err != io.ErrShortWrite {
				return fmt.Errorf("write(%s) = %d, %w", completeFile.Name(), n, err)
			}
			bytes = bytes[n:]
		}
		if err := completeFile.Close(); err != nil {
			return fmt.Errorf("close(%s) = %w", completeFile.Name(), err)
		}
		return waitFn()
	})

	select {
	case <-ctx.Done():
		// The only reason for our context to be cancelled is the propagation of
		// the cancellation from the errgroup g, which means DUT returned an error
		// so we report it with g.Wait().
		if ctx.Err() == context.Canceled {
			return fmt.Errorf("failed to bootstrap DUT: %w", g.Wait())
		}
		panic(fmt.Sprintf("unknown reason for the context to be cancelled: %s, g.Wait() = %s", ctx.Err(), g.Wait()))
	// An signal occurred, we should exit.
	case <-stopSigs:
		return nil
	}
}

// WaitForServer waits for a pattern to occur in posix_server's logs.
func WaitForServer(output io.Reader) error {
	// TODO(gvisor.dev/issue/6835): waiting for the server via log output is
	// fragile, a better way could be passing a file descriptor, which is not
	// possible with docker, do that after the docker runner is removed.
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		if text := scanner.Text(); strings.HasPrefix(text, "Server listening on") {
			return nil
		}
	}
	return scanner.Err()
}
