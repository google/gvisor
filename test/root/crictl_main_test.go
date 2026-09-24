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

package root

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/moby/sys/capability"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestMain is the main function for crictl tests.
func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	if !flag.CommandLine.Parsed() {
		flag.Parse()
	}

	if useHarness() {
		dockerutil.EnsureSupportedDockerVersion()
		code := runInHarness(context.Background())
		if code == 0 {
			if f := os.Getenv("TEST_PREMATURE_EXIT_FILE"); f != "" {
				_ = os.Remove(f)
			}
		}
		os.Exit(code)
	}

	if !specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_DAC_OVERRIDE) {
		fmt.Println("Test requires sysadmin privileges to run. Try again with sudo, or use the harness.")
		os.Exit(1)
	}

	// If we get here, we do not need to call the harness, which means we are either running in a
	// harness docker container or running directly against a host containerd.
	if !inHarness() {
		dockerutil.EnsureSupportedDockerVersion()
	}

	path, err := dockerutil.RuntimePath()
	if err != nil {
		panic(err.Error())
	}
	specutils.ExePath = path

	os.Exit(m.Run())
}
