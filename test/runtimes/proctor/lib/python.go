// Copyright 2019 The gVisor Authors.
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

package lib

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// exclude holds test cases that fail in gVisor for various reasons and should
// be excluded. The format of this map is [test library] -> [test cases...].
// We need to handle test exclusion differently for python. Running python
// tests on a test-case basis using `./python -m test --fromfile FILE` is too
// slow. For example, it took 0.065s seconds to run
// `./python -m test test_grammar` but it took 9.5 seconds to run the same set
// of tests using `--fromfile`. The fast way of running a test library while
// excluding a few test cases is to run `./python -m {lib} {test cases...}`. We
// don't `--list-cases` + the CSV exclude file mechanism because tests are
// selected from the list based on sharding/partition. We end up getting a
// small list of tests from various test libraries. Tests from same library
// are not grouped well together. So instead, we use `--list-tests` (which
// lists test libraries). When running a test library, using this map we
// generate a command to run all un-excluded tests from that library together.
var exclude = map[string][]string{
	// TODO(b/271473320): Un-exclude once this bug is fixed. Fails with overlay.
	"test_os": {"TestScandir.test_attributes"},
	// Broken test. Fails with runc too.
	"test_asyncio.test_base_events": {
		"BaseEventLoopWithSelectorTests\\.test_create_connection_service_name",
	},
	// TODO(b/162978767): Un-exclude once this bug is fixed.
	"test_fcntl": {"TestFcntl\\.test_fcntl_64_bit"},
	// TODO(b/341776233): Un-exclude once this bug is fixed.
	"test_pathlib": {
		"PathSubclassTest\\.test_is_mount",
		"PathTest\\.test_is_mount",
		"PosixPathTest\\.test_is_mount",
	},
	// TODO(b/76174079): Un-exclude once this bug is fixed.
	"test_posix": {
		"PosixTester\\.test_sched_priority",
		"PosixTester\\.test_sched_rr_get_interval",
		"PosixTester\\.test_get_and_set_scheduler_and_param", // sched_setparam(2) is not supported.
		"TestPosixSpawn\\.test_setscheduler_only_param",
		"TestPosixSpawnP\\.test_setscheduler_only_param",
	},
	// TODO(b/76174079): Un-exclude once this bug is fixed.
	"test_resource": {"ResourceTest\\.test_prlimit"},
	// TODO(b/271949964): Un-exclude test cases as they are fixed.
	"test_socket": {
		"BasicUDPLITETest\\..*",
		"GeneralModuleTests\\.testGetServBy",   // Broken test.
		"GeneralModuleTests\\.testGetaddrinfo", // Broken test.
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSecondCmsgTrunc1",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSecondCmsgTrunc2Int",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSecondCmsgTruncInData",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSecondCmsgTruncLen0Minus1",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSingleCmsgTrunc1",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSingleCmsgTrunc2Int",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSingleCmsgTruncInData",
		"RecvmsgIntoRFC3542AncillaryUDP6Test\\.testSingleCmsgTruncLen0Minus1",
		"RecvmsgIntoRFC3542AncillaryUDPLITE6Test\\..*",
		"RecvmsgIntoUDPLITE6Test\\..*",
		"RecvmsgIntoUDPLITETest\\..*",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSecondCmsgTrunc1",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSecondCmsgTrunc2Int",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSecondCmsgTruncInData",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSecondCmsgTruncLen0Minus1",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSingleCmsgTrunc1",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSingleCmsgTrunc2Int",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSingleCmsgTruncInData",
		"RecvmsgRFC3542AncillaryUDP6Test\\.testSingleCmsgTruncLen0Minus1",
		"RecvmsgRFC3542AncillaryUDPLITE6Test\\..*",
		"RecvmsgUDPLITE6Test\\..*",
		"RecvmsgUDPLITETest\\..*",
		"SendmsgUDPLITE6Test\\..*",
		"SendmsgUDPLITETest\\..*",
		"UDPLITETimeoutTest\\..*",
	},
	// TODO(b/341780803): Un-exclude once this bug is fixed.
	"test_termios": {
		"TestFunctions\\.test_tcdrain",
		"TestFunctions\\.test_tcflow",
		"TestFunctions\\.test_tcflush",
		"TestFunctions\\.test_tcsendbreak",
		"TestFunctions\\.test_tcflow_errors",
		"TestFunctions\\.test_tcflush_errors",
	},
}

// pythonRunner implements TestRunner for Python.
type pythonRunner struct{}

var _ TestRunner = pythonRunner{}

// ListTests implements TestRunner.ListTests.
func (pythonRunner) ListTests() ([]string, error) {
	args := []string{"-m", "test", "--list-tests"}
	cmd := exec.Command("./python", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list: %v", err)
	}
	var res []string
	for _, testLib := range strings.Split(string(out), "\n") {
		if len(testLib) == 0 {
			continue
		}
		// Some test libraries (like "test_asyncio") have sub-libraries which are
		// expanded in the output with a "test." prefix. Remove it.
		res = append(res, strings.TrimPrefix(testLib, "test."))
	}
	// Sort to have deterministic results across shards.
	sort.Strings(res)
	return res, nil
}

// TestCmds implements TestRunner.TestCmds.
func (pythonRunner) TestCmds(tests []string) []*exec.Cmd {
	var cmds []*exec.Cmd
	var full []string
	for _, testModule := range tests {
		if excludeTCs, ok := exclude[testModule]; ok {
			cmds = append(cmds, testCmdWithExclTCs(testModule, excludeTCs))
		} else {
			full = append(full, testModule)
		}
	}
	if len(full) > 0 {
		// Run all test modules (that have no excludes) together for speed.
		// Running them individually with a new exec.Cmd takes longer.
		args := append([]string{"-m", "test"}, full...)
		cmds = append(cmds, exec.Command("./python", args...))
	}
	return cmds
}

func testCmdWithExclTCs(testModule string, excludeTCs []string) *exec.Cmd {
	shellPipeline := []string{
		// List all test cases in this module.
		fmt.Sprintf("./python -m test %s --list-cases", testModule),
		// Exclude the test cases. Note that '$' was added after each excluded test
		// case to be exact about which test case to exclude.
		fmt.Sprintf("grep -v \"%s$\"", strings.Join(excludeTCs, "$\\|")),
		// Remove the "test.{testModule}." prefix.
		fmt.Sprintf("sed -e \"s/^test.%s.//\"", testModule),
		// Run all un-excluded test cases in one command.
		fmt.Sprintf("xargs ./python -m test.%s", testModule),
	}
	args := []string{"-c", strings.Join(shellPipeline, " | ")}
	return exec.Command("sh", args...)
}
