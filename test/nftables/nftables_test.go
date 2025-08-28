// Copyright 2025 The gVisor Authors.
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

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// singleTest runs a TestCase. Each test follows a pattern:
//   - Create a container.
//   - Get the container's IP.
//   - Send the container our IP.
//   - Start a new goroutine running the local action of the test.
//   - Wait for both the container and local actions to finish.
//
// Container output is logged to $TEST_UNDECLARED_OUTPUTS_DIR if it exists, or
// to stderr.
func singleTest(t *testing.T, test TestCase) {
	for _, tc := range []bool{false, true} {
		subtest := "IPv4"
		if tc {
			subtest = "IPv6"
		}
		t.Run(subtest, func(t *testing.T) {
			nftablesTest(t, test, tc)
		})
	}
}

func nftablesTest(t *testing.T, test TestCase, ipv6 bool) {
	if _, ok := Tests[test.Name()]; !ok {
		log.Infof("no test found with name %q. Has it been registered?", test.Name())
		t.FailNow()
	}

	// Wait for the local and container goroutines to finish.
	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)
	defer cancel()

	d := dockerutil.MakeContainer(ctx, t)
	defer func() {
		if logs, err := d.Logs(context.Background()); err != nil {
			log.Infof("Failed to retrieve container logs.")
		} else {
			log.Infof("=== Container logs: ===\n%s", logs)
		}
		// Use a new context, as cleanup should run even when we
		// timeout.
		d.CleanUp(context.Background())
	}()

	// Create and start the container.
	opts := dockerutil.RunOpts{
		Image:  "nftables",
		CapAdd: []string{"NET_ADMIN"},
	}
	d.CopyFiles(&opts, "/runner", "test/nftables/runner/runner")
	args := []string{"/runner/runner", "-name", test.Name()}
	if ipv6 {
		args = append(args, "-ipv6")
	}
	if err := d.Spawn(ctx, opts, args...); err != nil {
		log.Infof("docker run failed: %v", err)
		t.FailNow()
	}

	// Get the container IP.
	ip, err := d.FindIP(ctx, ipv6)
	if err != nil {
		// If ipv6 is not configured, don't fail.
		if ipv6 && err == dockerutil.ErrNoIP {
			log.Infof("No ipv6 address is available.")
			t.Skip()
		}
		log.Infof("failed to get container IP: %v", err)
		t.FailNow()
	}

	// Give the container our IP.
	if err := sendIP(ip); err != nil {
		log.Infof("failed to send IP to container: %v", err)
		t.FailNow()
	}

	// Run our side of the test.
	errCh := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := test.LocalAction(ctx, ip, ipv6); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("LocalAction failed: %v", err)
		} else {
			errCh <- nil
		}
		if test.LocalSufficient() {
			errCh <- nil
		}
	}()

	// Run the container side.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for the final statement. This structure has the side
		// effect that all container logs will appear within the
		// individual test context.
		if _, err := d.WaitForOutput(ctx, TerminalStatement, TestTimeout); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("ContainerAction failed: %v", err)
		} else {
			errCh <- nil
		}
		if test.ContainerSufficient() {
			errCh <- nil
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestFilterInputDropAll(t *testing.T) {
	singleTest(t, &FilterInputDropAll{})
}

func sendIP(ip net.IP) error {
	contAddr := net.TCPAddr{
		IP:   ip,
		Port: IPExchangePort,
	}
	var conn *net.TCPConn
	// The container may not be listening when we first connect, so retry
	// upon error.
	cb := func() error {
		c, err := net.DialTCP("tcp", nil, &contAddr)
		conn = c
		return err
	}
	if err := testutil.Poll(cb, TestTimeout); err != nil {
		return fmt.Errorf("timed out waiting to send IP, most recent error: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("error writing to container: %v", err)
	}
	return nil
}
