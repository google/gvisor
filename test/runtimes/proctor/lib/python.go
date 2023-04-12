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
	"test_os": []string{"TestScandir.test_attributes"},
	// Broken test. Fails with runc too.
	"test_asyncio.test_base_events": []string{
		"BaseEventLoopWithSelectorTests.test_create_connection_service_name",
	},
	// TODO(b/271950879): Un-exclude once this bug is fixed.
	"test_asyncio.test_events": []string{
		"EPollEventLoopTests.test_bidirectional_pty",
		"PollEventLoopTests.test_bidirectional_pty",
		"SelectEventLoopTests.test_bidirectional_pty",
	},
	// TODO(b/162973328): Un-exclude once this bug is fixed.
	"test_asyncore": []string{
		"TestAPI_UseIPv4Poll.test_handle_expt",
		"TestAPI_UseIPv4Select.test_handle_expt",
	},
	// TODO(b/162978767): Un-exclude once this bug is fixed.
	"test_fcntl": []string{"TestFcntl.test_fcntl_64_bit"},
	// TODO(b/76174079): Un-exclude once this bug is fixed.
	"test_posix": []string{
		"PosixTester.test_sched_priority",
		"PosixTester.test_sched_rr_get_interval",
		"PosixTester.test_get_and_set_scheduler_and_param", // sched_setparam(2) is not supported.
		"TestPosixSpawn.test_setscheduler_only_param",
		"TestPosixSpawnP.test_setscheduler_only_param",
	},
	// TODO(b/162979921): Un-exclude once this bug is fixed.
	"test_pty": []string{
		"PtyTest.test_fork",
		"PtyTest.test_master_read",
		"PtyTest.test_spawn_doesnt_hang",
	},
	// TODO(b/162980389): Un-exclude once this bug is fixed.
	"test_readline": []string{"TestReadline.*"},
	// TODO(b/76174079): Un-exclude once this bug is fixed.
	"test_resource": []string{"ResourceTest.test_prlimit"},
	// TODO(b/271949964): Un-exclude test cases as they are fixed.
	"test_socket": []string{
		"BasicUDPLITETest.testRecvFrom",
		"BasicUDPLITETest.testRecvFromNegative",
		"BasicUDPLITETest.testSendtoAndRecv",
		"GeneralModuleTests.testGetServBy",
		"GeneralModuleTests.testGetaddrinfo",
		"RecvmsgIntoUDPLITETest.testRecvmsg",
		"RecvmsgIntoUDPLITETest.testRecvmsgAfterClose",
		"RecvmsgIntoUDPLITETest.testRecvmsgExplicitDefaults",
		"RecvmsgIntoUDPLITETest.testRecvmsgFromSendmsg",
		"RecvmsgIntoUDPLITETest.testRecvmsgIntoArray",
		"RecvmsgIntoUDPLITETest.testRecvmsgIntoBadArgs",
		"RecvmsgIntoUDPLITETest.testRecvmsgIntoGenerator",
		"RecvmsgIntoUDPLITETest.testRecvmsgIntoScatter",
		"RecvmsgIntoUDPLITETest.testRecvmsgLongAncillaryBuf",
		"RecvmsgIntoUDPLITETest.testRecvmsgPeek",
		"RecvmsgIntoUDPLITETest.testRecvmsgShortAncillaryBuf",
		"RecvmsgIntoUDPLITETest.testRecvmsgShorter",
		"RecvmsgIntoUDPLITETest.testRecvmsgTimeout",
		"RecvmsgIntoUDPLITETest.testRecvmsgTrunc",
		"RecvmsgUDPLITETest.testRecvmsg",
		"RecvmsgUDPLITETest.testRecvmsgAfterClose",
		"RecvmsgUDPLITETest.testRecvmsgBadArgs",
		"RecvmsgUDPLITETest.testRecvmsgExplicitDefaults",
		"RecvmsgUDPLITETest.testRecvmsgFromSendmsg",
		"RecvmsgUDPLITETest.testRecvmsgLongAncillaryBuf",
		"RecvmsgUDPLITETest.testRecvmsgPeek",
		"RecvmsgUDPLITETest.testRecvmsgShortAncillaryBuf",
		"RecvmsgUDPLITETest.testRecvmsgShorter",
		"RecvmsgUDPLITETest.testRecvmsgTimeout",
		"RecvmsgUDPLITETest.testRecvmsgTrunc",
		"SendmsgUDPLITETest.testSendmsg",
		"SendmsgUDPLITETest.testSendmsgAfterClose",
		"SendmsgUDPLITETest.testSendmsgAncillaryGenerator",
		"SendmsgUDPLITETest.testSendmsgArray",
		"SendmsgUDPLITETest.testSendmsgBadArgs",
		"SendmsgUDPLITETest.testSendmsgBadCmsg",
		"SendmsgUDPLITETest.testSendmsgBadMultiCmsg",
		"SendmsgUDPLITETest.testSendmsgDataGenerator",
		"SendmsgUDPLITETest.testSendmsgExcessCmsgReject",
		"SendmsgUDPLITETest.testSendmsgGather",
		"SendmsgUDPLITETest.testSendmsgNoDestAddr",
		"UDPLITETimeoutTest.testTimeoutZero",
		"UDPLITETimeoutTest.testUDPLITETimeout",
	},
	// TODO(b/274167897): Un-exclude test cases once this is patched upstream.
	// The test is broken: https://github.com/python/cpython/issues/102795
	"test_epoll": []string{"TestEPoll.test_control_and_wait"},
}

// Some python test libraries contain other test libraries that have test cases
// that need to be excluded. We need to expand such libraries so that the test
// case exclusion can work correctly.
var expand = []string{
	"test_asyncio",
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
	testLibs := make(map[string]struct{})
	for _, testLib := range strings.Split(string(out), "\n") {
		if len(testLib) == 0 {
			continue
		}
		testLibs[testLib] = struct{}{}
	}
	for _, libToExpand := range expand {
		if _, ok := testLibs[libToExpand]; !ok {
			return nil, fmt.Errorf("%s test library was not listed", libToExpand)
		}
		delete(testLibs, libToExpand)
		subLibs, err := subTestLibs(libToExpand)
		if err != nil {
			return nil, err
		}
		for subLib := range subLibs {
			testLibs[fmt.Sprintf("%s.%s", libToExpand, subLib)] = struct{}{}
		}
	}
	res := make([]string, 0, len(testLibs))
	for lib := range testLibs {
		res = append(res, lib)
	}
	// Sort to have deterministic results across shards.
	sort.Strings(res)
	return res, nil
}

func subTestLibs(testLib string) (map[string]struct{}, error) {
	// --list-{tests/cases} is only implemented by the 'test' library.
	// Running './python -m test {X} --list-tests' does not list libraries inside
	// X library. We need to list all test cases and extract sub libraries.
	args := []string{"-m", "test", testLib, "--list-cases"}
	cmd := exec.Command("./python", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list: %v", err)
	}
	subLibs := make(map[string]struct{})
	for _, tc := range strings.Split(string(out), "\n") {
		if len(tc) == 0 {
			continue
		}
		idx := strings.Index(tc, testLib)
		if idx < 0 {
			return nil, fmt.Errorf("could not find %q library in test case %q", testLib, tc)
		}
		subLibs[strings.Split(tc[idx:], ".")[1]] = struct{}{}
	}
	return subLibs, nil
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
