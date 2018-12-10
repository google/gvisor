// Copyright 2018 Google LLC
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

// Package syscall_test runs the syscall test suites in gVisor containers. It
// is meant to be run with "go test", and will panic if run on its own.
package syscall_test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
	"gvisor.googlesource.com/gvisor/test/syscalls/gtest"
)

// Location of syscall tests, relative to the repo root.
const testDir = "test/syscalls/linux"

var (
	testName = flag.String("test-name", "", "name of test binary to run")
	debug    = flag.Bool("debug", false, "enable debug logs")
	strace   = flag.Bool("strace", false, "enable strace logs")
	platform = flag.String("platform", "ptrace", "platform to run on")
	parallel = flag.Bool("parallel", false, "run tests in parallel")
)

func TestSyscalls(t *testing.T) {
	if *testName == "" {
		t.Fatalf("test-name flag must be provided")
	}

	// Get path to test binary.
	fullTestName := filepath.Join(testDir, *testName)
	testBin, err := testutil.FindFile(fullTestName)
	if err != nil {
		t.Fatalf("FindFile(%q) failed: %v", fullTestName, err)
	}

	// Get all test cases in each binary.
	testCases, err := gtest.ParseTestCases(testBin)
	if err != nil {
		t.Fatalf("ParseTestCases(%q) failed: %v", testBin, err)
	}

	// Make sure stdout and stderr are opened with O_APPEND, otherwise logs
	// from outside the sandbox can (and will) stomp on logs from inside
	// the sandbox.
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			t.Fatalf("error getting file flags for %v: %v", f, err)
		}
		if flags&unix.O_APPEND == 0 {
			flags |= unix.O_APPEND
			if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFL, flags); err != nil {
				t.Fatalf("error setting file flags for %v: %v", f, err)
			}
		}
	}

	for _, tc := range testCases {
		// Capture tc.
		tc := tc

		testName := fmt.Sprintf("%s_%s", tc.Suite, tc.Name)
		t.Run(testName, func(t *testing.T) {
			if *parallel {
				t.Parallel()
			}

			if *platform == "native" {
				// Run the test case on host.
				runTestCaseNative(testBin, tc, t)
				return
			}

			// Run the test case in runsc.
			runTestCaseRunsc(testBin, tc, t)
		})
	}
}

// runTestCaseNative runs the test case directly on the host machine.
func runTestCaseNative(testBin string, tc gtest.TestCase, t *testing.T) {
	// These tests might be running in parallel, so make sure they have a
	// unique test temp dir.
	tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "")
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Replace TEST_TMPDIR in the current environment with something
	// unique.
	env := os.Environ()
	newEnvVar := "TEST_TMPDIR=" + tmpDir
	var found bool
	for i, kv := range env {
		if strings.HasPrefix(kv, "TEST_TMPDIR=") {
			env[i] = newEnvVar
			found = true
			break
		}
	}
	if !found {
		env = append(env, newEnvVar)
	}
	// Remove the TEST_PREMATURE_EXIT_FILE variable and XML_OUTPUT_FILE
	// from the environment.
	env = filterEnv(env, []string{"TEST_PREMATURE_EXIT_FILE", "XML_OUTPUT_FILE"})

	cmd := exec.Command(testBin, gtest.FilterTestFlag+"="+tc.FullName())
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ws := err.(*exec.ExitError).Sys().(syscall.WaitStatus)
		t.Errorf("test %q exited with status %d, want 0", tc.FullName(), ws.ExitStatus())
	}
}

// runsTestCaseRunsc runs the test case in runsc.
func runTestCaseRunsc(testBin string, tc gtest.TestCase, t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir failed: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfig()
	conf.RootDir = rootDir
	conf.Debug = *debug
	conf.Strace = *strace
	p, err := boot.MakePlatformType(*platform)
	if err != nil {
		t.Fatalf("error getting platform %q: %v", *platform, err)
	}
	conf.Platform = p

	// Run a new container with the test executable and filter for the
	// given test suite and name.
	spec := testutil.NewSpecWithArgs(testBin, gtest.FilterTestFlag+"="+tc.FullName())

	// Mark the root as writeable, as some tests attempt to
	// write to the rootfs, and expect EACCES, not EROFS.
	spec.Root.Readonly = false

	// Set environment variable that indicates we are
	// running in gVisor and with the given platform.
	platformVar := "TEST_ON_GVISOR"
	env := append(os.Environ(), platformVar+"="+*platform)

	// Remove the TEST_PREMATURE_EXIT_FILE variable and XML_OUTPUT_FILE
	// from the environment.
	env = filterEnv(env, []string{"TEST_PREMATURE_EXIT_FILE", "XML_OUTPUT_FILE"})

	// Set TEST_TMPDIR to /tmp, as some of the syscall tests require it to
	// be backed by tmpfs.
	for i, kv := range env {
		if strings.HasPrefix(kv, "TEST_TMPDIR=") {
			env[i] = "TEST_TMPDIR=/tmp"
			break
		}
	}

	spec.Process.Env = env

	bundleDir, err := testutil.SetupBundleDir(spec)
	if err != nil {
		t.Fatalf("SetupBundleDir failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	id := testutil.UniqueContainerID()
	log.Infof("Running test %q in container %q", tc.FullName(), id)
	specutils.LogSpec(spec)
	ws, err := container.Run(id, spec, conf, bundleDir, "", "", "")
	if err != nil {
		t.Fatalf("container.Run failed: %v", err)
	}
	if got := ws.ExitStatus(); got != 0 {
		t.Errorf("test %q exited with status %d, want 0", tc.FullName(), ws.ExitStatus())
	}
}

// filterEnv returns an environment with the blacklisted variables removed.
func filterEnv(env, blacklist []string) []string {
	var out []string
	for _, kv := range env {
		ok := true
		for _, k := range blacklist {
			if strings.HasPrefix(kv, k+"=") {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, kv)
		}
	}
	return out
}

func TestMain(m *testing.M) {
	flag.Parse()

	log.SetLevel(log.Warning)
	if *debug {
		log.SetLevel(log.Debug)
	}
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}

	if *platform != "native" {
		// The native tests don't expect to be running as root, but
		// runsc requires it.
		testutil.RunAsRoot()
	}

	os.Exit(m.Run())
}
