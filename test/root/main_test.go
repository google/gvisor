// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"os"
	"testing"

	"github.com/syndtr/gocapability/capability"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestMain is the main function for root tests. This function checks the
// supported docker version, required capabilities, and configures the executable
// path for runsc.
func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	if !flag.CommandLine.Parsed() {
		flag.Parse()
	}

	if !specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_DAC_OVERRIDE) {
		fmt.Println("Test requires sysadmin privileges to run. Try again with sudo.")
		os.Exit(1)
	}

	dockerutil.EnsureSupportedDockerVersion()

	// Configure exe for tests.
	path, err := dockerutil.RuntimePath()
	if err != nil {
		panic(err.Error())
	}
	specutils.ExePath = path

	os.Exit(m.Run())
}
