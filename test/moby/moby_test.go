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

// Package moby_test runs the Moby integration tests in a Docker container.
package moby_test

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/runtimes/runner/lib"
)

var (
	testsFilter = flag.String("tests", testutil.StringFromEnv("RUNTIME_TESTS_FILTER", ""),
		"if specified, runs only the given comma-separated list of test names")
	batchSize = flag.Int("batch", 50, "number of test cases run in one command")
	timeout   = flag.Duration("timeout", 20*time.Minute, "batch timeout")
)

// excludedTests is the set of Moby network integration tests currently skipped.
var excludedTests = map[string]bool{
	// TODO: b/568433403 - Enable when fixed.
	"integration/network/dns_test/TestExtDNSInIPv6OnlyNw":               true,
	"integration/network/network_linux_test/TestConnectWithPriority":    true,
	"integration/network/network_linux_test/TestCreateWithPriority":     true,
	"integration/network/network_linux_test/TestHostGatewayFromDocker0": true,
	"integration/network/network_linux_test/TestMixL3IPVlanAndBridge":   true,

	// TODO: b/568433242 - Enable when fixed.
	"integration/network/network_linux_test/TestDefaultNetworkOpts": true,

	// TODO: b/568428174 - Enable when fixed.
	"integration/network/network_test/TestAPINetworkFilter":               true,
	"integration/network/network_test/TestAPINetworkGetDefaults":          true,
	"integration/network/network_test/TestCreateDeletePredefinedNetworks": true,
}

func dockerInGvisorCapabilities() []string {
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

func TestMain(m *testing.M) {
	flag.Parse()
	if dockerutil.Runtime() == "" {
		slog.Warn("no runtime specified, defaulting to runsc")
		dockerutil.SetRuntime("runsc")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	isGVisor, err := dockerutil.IsGVisorRuntime(ctx)
	cancel()
	if err != nil {
		slog.Error("IsGVisorRuntime failed", "err", err)
		os.Exit(1)
	}
	proctorSettings := lib.ProctorSettings{
		Runner: "test/moby/runner",
		// Docker in Docker requires privileged mode.
		Privileged:        !isGVisor,
		CapAdd:            dockerInGvisorCapabilities(),
		PerTestTimeout:    5 * time.Minute,
		RunsPerTest:       1,
		FlakyIsError:      true,
		FlakyShortCircuit: true,
	}
	filter := func(test string) bool {
		return !excludedTests[test]
	}
	if *testsFilter != "" {
		tests := make(map[string]bool)
		for _, test := range strings.Split(*testsFilter, ",") {
			tests[test] = true
		}
		filter = func(test string) bool {
			return tests[test]
		}
	}
	os.Exit(lib.RunTests("moby", "moby", filter, *batchSize, *timeout, proctorSettings))
}

// TestMoby is a placeholder required by go_test main generation; actual test
// discovery and sharding are handled by TestMain via lib.RunTests.
func TestMoby(t *testing.T) {}
