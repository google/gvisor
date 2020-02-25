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

// Binary syscall_test_runner runs the syscall test suites in gVisor
// containers and on the host platform.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/testutil"
	"gvisor.dev/gvisor/test/runner/gtest"
	"gvisor.dev/gvisor/test/uds"
)

var (
	debug      = flag.Bool("debug", false, "enable debug logs")
	strace     = flag.Bool("strace", false, "enable strace logs")
	platform   = flag.String("platform", "ptrace", "platform to run on")
	network    = flag.String("network", "none", "network stack to run on (sandbox, host, none)")
	useTmpfs   = flag.Bool("use-tmpfs", false, "mounts tmpfs for /tmp")
	fileAccess = flag.String("file-access", "exclusive", "mounts root in exclusive or shared mode")
	overlay    = flag.Bool("overlay", false, "wrap filesystem mounts with writable tmpfs overlay")
	parallel   = flag.Bool("parallel", false, "run tests in parallel")
	runscPath  = flag.String("runsc", "", "path to runsc binary")
	addUDSTree = flag.Bool("add-uds-tree", false, "expose a tree of UDS utilities for use in tests")
)

// filterEnv returns an environment with the blacklisted variables removed.
func filterEnv(env []string, blacklist ...string) []string {
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

// setupEnv sets up the test environment.
func setupEnv(tc gtest.TestCase) ([]string, string, error) {
	tmpDir := os.Getenv("TEST_TMPDIR")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	// Setup a temporary directory for just this specific test.
	tmpDir = filepath.Join(tmpDir, tc.FileName())
	if err := os.MkdirAll(tmpDir, 0777); err != nil {
		return nil, "", fmt.Errorf("could not create temporary dir: %v", err)
	}

	// Construct a specific XML output file for this test.
	xmlOutput := os.Getenv("XML_OUTPUT_FILE")
	if xmlOutput != "" {
		// Define a test-specific xml output that can be merged later.
		xmlOutput = fmt.Sprintf("%s.%s", xmlOutput, tc.FileName())
	}

	// Start with our own test environment.
	env := os.Environ()

	// Remove env variables that will cause the gunit binary to write
	// output files, since they will stomp on eachother, and on the output
	// files from this go test. Note that we will readd this below.
	env = filterEnv(env, "GUNIT_OUTPUT", "GTEST_OUTPUT", "TEST_TMPDIR", "TEST_PREMATURE_EXIT_FILE", "XML_OUTPUT_FILE")

	// Remove shard env variables so that the gunit binary does not try to
	// intepret them. We construct shards manually.
	env = filterEnv(env, "TEST_SHARD_INDEX", "TEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_TOTAL_SHARDS")

	// Re-add the above test-specific bits that were stripped.
	env = append(env, fmt.Sprintf("TEST_TMPDIR=%s", tmpDir))
	env = append(env, fmt.Sprintf("XML_OUTPUT_FILE=%s", xmlOutput))
	env = append(env, fmt.Sprintf("GUNIT_OUTPUT=xml:%s", xmlOutput))
	env = append(env, fmt.Sprintf("GTEST_OUTPUT=xml:%s", xmlOutput))
	return env, tmpDir, nil
}

// runNative runs the test case directly on the host machine.
func runNative(testBin string, tc gtest.TestCase) error {
	// Setup the test environment.
	env, tmpDir, err := setupEnv(tc)
	if err != nil {
		return fmt.Errorf("could not setup test environment: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if *addUDSTree {
		socketDir, cleanup, err := uds.CreateSocketTree(tmpDir)
		if err != nil {
			return fmt.Errorf("failed to create socket tree: %v", err)
		}
		defer cleanup()

		// On Linux, the concept of "attach" location doesn't exist.
		// Just pass the same path to make these test identical.
		env = append(env, "TEST_UDS_ATTACH_TREE="+socketDir)
		env = append(env, "TEST_UDS_TREE="+socketDir)
	}

	cmd := exec.Command(testBin, tc.Args()...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runRunsc runs spec in runsc in a standard test configuration.
//
// runsc logs will be saved to a path in TEST_UNDECLARED_OUTPUTS_DIR.
//
// Returns an error if the sandboxed application exits non-zero.
func runRunsc(testBin string, tc gtest.TestCase) error {
	// Setup the test environment.
	env, tmpDir, err := setupEnv(tc)
	if err != nil {
		return fmt.Errorf("could not setup test environment: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Run a new container with the test executable and filter for the
	// given test suite and name.
	spec := testutil.NewSpecWithArgs(append([]string{testBin}, tc.Args()...)...)

	// Set environment variables that indicate we are running in gVisor
	// with the given platform and network.
	spec.Process.Env = append(env,
		"TEST_ON_GVISOR="+*platform,
		"GVISOR_NETWORK="+*network,
	)

	// Mark the root as writeable, as some tests attempt to write to the
	// rootfs, and expect EACCES, not EROFS.
	spec.Root.Readonly = false

	// Test spec comes with pre-defined mounts that we don't want.
	spec.Mounts = nil
	if *useTmpfs {
		// Forces '/tmp' to be mounted as tmpfs, otherwise test that
		// rely on features only available in gVisor's internal tmpfs
		// may fail.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: tmpDir,
			Type:        "tmpfs",
		})
	}

	// Create the container spec.
	bundleDir, err := testutil.SetupBundleDir(spec)
	if err != nil {
		return fmt.Errorf("SetupBundleDir failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		return fmt.Errorf("SetupRootDir failed: %v", err)
	}
	defer os.RemoveAll(rootDir)

	// Construct appropriate arguments.
	args := []string{
		"-root", rootDir,
		"-network", *network,
		"-log-format=text",
		"-TESTONLY-unsafe-nonroot=true",
		"-net-raw=true",
		fmt.Sprintf("-panic-signal=%d", syscall.SIGTERM),
		"-watchdog-action=panic",
		"-platform", *platform,
		"-file-access", *fileAccess,
	}
	if *overlay {
		args = append(args, "-overlay")
	}
	if *debug {
		args = append(args, "-debug", "-log-packets=true")
	}
	if *strace {
		args = append(args, "-strace")
	}
	if *addUDSTree {
		cleanup, err := setupUDSTree(spec)
		if err != nil {
			return fmt.Errorf("error creating UDS tree: %v", err)
		}
		defer cleanup()
		args = append(args, "-fsgofer-host-uds")
	}

	// Setup debug logging.
	if outDir, ok := syscall.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		tdir := filepath.Join(outDir, tc.FileName())
		if err := os.MkdirAll(tdir, 0755); err != nil {
			return fmt.Errorf("could not create test dir: %v", err)
		}
		debugLogDir, err := ioutil.TempDir(tdir, "runsc")
		if err != nil {
			return fmt.Errorf("could not create temp dir: %v", err)
		}
		debugLogDir += "/"
		log.Infof("runsc logs: %s", debugLogDir)
		args = append(args, "-debug-log", debugLogDir)

		// Default -log sends messages to stderr which makes reading
		// the test log difficult. Instead, drop them when debug log is
		// enabled given it's a better place for these messages.
		args = append(args, "-log=/dev/null")
	}

	// Prepare to run the test.
	id := testutil.UniqueContainerID()
	log.Infof("Running test %q in container %q", tc.FullName(), id)
	specutils.LogSpec(spec)

	// Current process doesn't have CAP_SYS_ADMIN, create user namespace
	// and run as root inside that namespace to get it.
	rArgs := append(args, "run", "--bundle", bundleDir, id)
	cmd := exec.Command(*runscPath, rArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		// Set current user/group as root inside the namespace.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	sig := make(chan os.Signal, 1)
	defer close(sig)
	signal.Notify(sig, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		// Wait for a signal.
		s, ok := <-sig
		if !ok {
			// The channel closed, so the command must have
			// completed successfully. That is, we reached the
			// close(sig) statement via the defer.
			return
		}

		// Dump stacks if possible.
		log.Warningf("Got signal: %v", s)
		done := make(chan bool)
		dArgs := append([]string{}, args...)
		dArgs = append(dArgs, "-alsologtostderr=true", "debug", "--stacks", id)
		go func(dArgs []string) {
			cmd := exec.Command(*runscPath, dArgs...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			done <- true
		}(dArgs)

		// Wait for up to three seconds.
		timeout := time.After(3 * time.Second)
		select {
		case <-timeout:
			log.Infof("runsc debug --stacks timed out")
		case <-done:
			return
		}

		// Kill via SIGTERM.
		log.Warningf("Send SIGTERM to the sandbox process")
		dArgs = append(args, "debug", fmt.Sprintf("--signal=%d", syscall.SIGTERM), id)
		cmd := exec.Command(*runscPath, dArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}()

	return cmd.Run()
}

// setupUDSTree updates the spec to expose a UDS tree for gofer socket testing.
//
// N.B. This modifies spec.Process.Env.
func setupUDSTree(spec *specs.Spec) (cleanup func(), err error) {
	socketDir, cleanup, err := uds.CreateSocketTree("/tmp")
	if err != nil {
		return nil, fmt.Errorf("failed to create socket tree: %v", err)
	}

	// Standard access to entire tree.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets",
		Source:      socketDir,
		Type:        "bind",
	})

	// Individial attach points for each socket to test mounts that attach
	// directly to the sockets.
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/stream/echo",
		Source:      filepath.Join(socketDir, "stream/echo"),
		Type:        "bind",
	})
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/stream/nonlistening",
		Source:      filepath.Join(socketDir, "stream/nonlistening"),
		Type:        "bind",
	})
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/seqpacket/echo",
		Source:      filepath.Join(socketDir, "seqpacket/echo"),
		Type:        "bind",
	})
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/seqpacket/nonlistening",
		Source:      filepath.Join(socketDir, "seqpacket/nonlistening"),
		Type:        "bind",
	})
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/tmp/sockets-attach/dgram/null",
		Source:      filepath.Join(socketDir, "dgram/null"),
		Type:        "bind",
	})

	spec.Process.Env = append(spec.Process.Env, "TEST_UDS_TREE=/tmp/sockets")
	spec.Process.Env = append(spec.Process.Env, "TEST_UDS_ATTACH_TREE=/tmp/sockets-attach")

	return cleanup, nil
}

func fatalf(s string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, s+"\n", args...)
	os.Exit(1)
}

func matchString(a, b string) (bool, error) {
	return a == b, nil
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("test must be provided")
	}
	testBin := flag.Args()[0] // Only argument.

	log.SetLevel(log.Info)
	if *debug {
		log.SetLevel(log.Debug)
	}

	if *platform != "native" && *runscPath == "" {
		if err := testutil.ConfigureExePath(); err != nil {
			panic(err.Error())
		}
		*runscPath = specutils.ExePath
	}

	// Make sure stdout and stderr are opened with O_APPEND, otherwise logs
	// from outside the sandbox can (and will) stomp on logs from inside
	// the sandbox.
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			fatalf("error getting file flags for %v: %v", f, err)
		}
		if flags&unix.O_APPEND == 0 {
			flags |= unix.O_APPEND
			if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFL, flags); err != nil {
				fatalf("error setting file flags for %v: %v", f, err)
			}
		}
	}

	// Get all test cases in each binary.
	testCases, err := gtest.ParseTestCases(testBin, true)
	if err != nil {
		fatalf("ParseTestCases(%q) failed: %v", testBin, err)
	}

	// Get subset of tests corresponding to shard.
	indices, err := testutil.TestIndicesForShard(len(testCases))
	if err != nil {
		fatalf("TestsForShard() failed: %v", err)
	}

	// Resolve the absolute path for the binary.
	testBin, err = filepath.Abs(testBin)
	if err != nil {
		fatalf("Abs() failed: %v", err)
	}

	// Run the tests.
	var tests []testing.InternalTest
	for _, tci := range indices {
		// Capture tc.
		tc := testCases[tci]
		tests = append(tests, testing.InternalTest{
			Name: fmt.Sprintf("%s_%s", tc.Suite, tc.Name),
			F: func(t *testing.T) {
				if *parallel {
					t.Parallel()
				}
				var err error
				if *platform == "native" {
					// Run the test case on host.
					err = runNative(testBin, tc)
				} else {
					// Run the test case in runsc.
					err = runRunsc(testBin, tc)
				}
				if err != nil {
					t.Errorf("test %q failed with error %v, want nil", tc.FullName(), err)
				}
			},
		})
	}

	testing.Main(matchString, tests, nil, nil)
}
