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
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
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
	vfs2       = flag.Bool("vfs2", false, "enable VFS2")
	fuse       = flag.Bool("fuse", false, "enable FUSE")
	parallel   = flag.Bool("parallel", false, "run tests in parallel")
	runscPath  = flag.String("runsc", "", "path to runsc binary")

	addUDSTree = flag.Bool("add-uds-tree", false, "expose a tree of UDS utilities for use in tests")
)

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
	// Remove env variables that cause the gunit binary to write output
	// files, since they will stomp on eachother, and on the output files
	// from this go test.
	env = filterEnv(env, []string{"GUNIT_OUTPUT", "TEST_PREMATURE_EXIT_FILE", "XML_OUTPUT_FILE"})

	// Remove shard env variables so that the gunit binary does not try to
	// intepret them.
	env = filterEnv(env, []string{"TEST_SHARD_INDEX", "TEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_TOTAL_SHARDS"})

	if *addUDSTree {
		socketDir, cleanup, err := uds.CreateSocketTree("/tmp")
		if err != nil {
			t.Fatalf("failed to create socket tree: %v", err)
		}
		defer cleanup()

		env = append(env, "TEST_UDS_TREE="+socketDir)
		// On Linux, the concept of "attach" location doesn't exist.
		// Just pass the same path to make these test identical.
		env = append(env, "TEST_UDS_ATTACH_TREE="+socketDir)
	}

	cmd := exec.Command(testBin, tc.Args()...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{}

	if specutils.HasCapabilities(capability.CAP_SYS_ADMIN) {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUTS
	}

	if specutils.HasCapabilities(capability.CAP_NET_ADMIN) {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	}

	if err := cmd.Run(); err != nil {
		ws := err.(*exec.ExitError).Sys().(syscall.WaitStatus)
		t.Errorf("test %q exited with status %d, want 0", tc.FullName(), ws.ExitStatus())
	}
}

// runRunsc runs spec in runsc in a standard test configuration.
//
// runsc logs will be saved to a path in TEST_UNDECLARED_OUTPUTS_DIR.
//
// Returns an error if the sandboxed application exits non-zero.
func runRunsc(tc gtest.TestCase, spec *specs.Spec) error {
	bundleDir, cleanup, err := testutil.SetupBundleDir(spec)
	if err != nil {
		return fmt.Errorf("SetupBundleDir failed: %v", err)
	}
	defer cleanup()

	rootDir, cleanup, err := testutil.SetupRootDir()
	if err != nil {
		return fmt.Errorf("SetupRootDir failed: %v", err)
	}
	defer cleanup()

	name := tc.FullName()
	id := testutil.RandomContainerID()
	log.Infof("Running test %q in container %q", name, id)
	specutils.LogSpec(spec)

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
	if *vfs2 {
		args = append(args, "-vfs2")
		if *fuse {
			args = append(args, "-fuse")
		}
	}
	if *debug {
		args = append(args, "-debug", "-log-packets=true")
	}
	if *strace {
		args = append(args, "-strace")
	}
	if *addUDSTree {
		args = append(args, "-fsgofer-host-uds")
	}

	testLogDir := ""
	if undeclaredOutputsDir, ok := syscall.Getenv("TEST_UNDECLARED_OUTPUTS_DIR"); ok {
		// Create log directory dedicated for this test.
		testLogDir = filepath.Join(undeclaredOutputsDir, strings.Replace(name, "/", "_", -1))
		if err := os.MkdirAll(testLogDir, 0755); err != nil {
			return fmt.Errorf("could not create test dir: %v", err)
		}
		debugLogDir, err := ioutil.TempDir(testLogDir, "runsc")
		if err != nil {
			return fmt.Errorf("could not create temp dir: %v", err)
		}
		debugLogDir += "/"
		log.Infof("runsc logs: %s", debugLogDir)
		args = append(args, "-debug-log", debugLogDir)

		// Default -log sends messages to stderr which makes reading the test log
		// difficult. Instead, drop them when debug log is enabled given it's a
		// better place for these messages.
		args = append(args, "-log=/dev/null")
	}

	// Current process doesn't have CAP_SYS_ADMIN, create user namespace and run
	// as root inside that namespace to get it.
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
		s, ok := <-sig
		if !ok {
			return
		}
		log.Warningf("%s: Got signal: %v", name, s)
		done := make(chan bool, 1)
		dArgs := append([]string{}, args...)
		dArgs = append(dArgs, "-alsologtostderr=true", "debug", "--stacks", id)
		go func(dArgs []string) {
			debug := exec.Command(*runscPath, dArgs...)
			debug.Stdout = os.Stdout
			debug.Stderr = os.Stderr
			debug.Run()
			done <- true
		}(dArgs)

		timeout := time.After(3 * time.Second)
		select {
		case <-timeout:
			log.Infof("runsc debug --stacks is timeouted")
		case <-done:
		}

		log.Warningf("Send SIGTERM to the sandbox process")
		dArgs = append(args, "debug",
			fmt.Sprintf("--signal=%d", syscall.SIGTERM),
			id)
		signal := exec.Command(*runscPath, dArgs...)
		signal.Stdout = os.Stdout
		signal.Stderr = os.Stderr
		signal.Run()
	}()

	err = cmd.Run()
	if err == nil && len(testLogDir) > 0 {
		// If the test passed, then we erase the log directory. This speeds up
		// uploading logs in continuous integration & saves on disk space.
		os.RemoveAll(testLogDir)
	}

	return err
}

// setupUDSTree updates the spec to expose a UDS tree for gofer socket testing.
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

// runsTestCaseRunsc runs the test case in runsc.
func runTestCaseRunsc(testBin string, tc gtest.TestCase, t *testing.T) {
	// Run a new container with the test executable and filter for the
	// given test suite and name.
	spec := testutil.NewSpecWithArgs(append([]string{testBin}, tc.Args()...)...)

	// Mark the root as writeable, as some tests attempt to
	// write to the rootfs, and expect EACCES, not EROFS.
	spec.Root.Readonly = false

	// Test spec comes with pre-defined mounts that we don't want. Reset it.
	spec.Mounts = nil
	testTmpDir := "/tmp"
	if *useTmpfs {
		// Forces '/tmp' to be mounted as tmpfs, otherwise test that rely on
		// features only available in gVisor's internal tmpfs may fail.
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/tmp",
			Type:        "tmpfs",
		})
	} else {
		// Use a gofer-backed directory as '/tmp'.
		//
		// Tests might be running in parallel, so make sure each has a
		// unique test temp dir.
		//
		// Some tests (e.g., sticky) access this mount from other
		// users, so make sure it is world-accessible.
		tmpDir, err := ioutil.TempDir(testutil.TmpDir(), "")
		if err != nil {
			t.Fatalf("could not create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		if err := os.Chmod(tmpDir, 0777); err != nil {
			t.Fatalf("could not chmod temp dir: %v", err)
		}

		// "/tmp" is not replaced with a tmpfs mount inside the sandbox
		// when it's not empty. This ensures that testTmpDir uses gofer
		// in exclusive mode.
		testTmpDir = tmpDir
		if *fileAccess == "shared" {
			// All external mounts except the root mount are shared.
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Type:        "bind",
				Destination: "/tmp",
				Source:      tmpDir,
			})
			testTmpDir = "/tmp"
		}
	}

	// Set environment variables that indicate we are running in gVisor with
	// the given platform, network, and filesystem stack.
	platformVar := "TEST_ON_GVISOR"
	networkVar := "GVISOR_NETWORK"
	env := append(os.Environ(), platformVar+"="+*platform, networkVar+"="+*network)
	vfsVar := "GVISOR_VFS"
	if *vfs2 {
		env = append(env, vfsVar+"=VFS2")
		fuseVar := "FUSE_ENABLED"
		if *fuse {
			env = append(env, fuseVar+"=TRUE")
		} else {
			env = append(env, fuseVar+"=FALSE")
		}
	} else {
		env = append(env, vfsVar+"=VFS1")
	}

	// Remove env variables that cause the gunit binary to write output
	// files, since they will stomp on eachother, and on the output files
	// from this go test.
	env = filterEnv(env, []string{"GUNIT_OUTPUT", "TEST_PREMATURE_EXIT_FILE", "XML_OUTPUT_FILE"})

	// Remove shard env variables so that the gunit binary does not try to
	// intepret them.
	env = filterEnv(env, []string{"TEST_SHARD_INDEX", "TEST_TOTAL_SHARDS", "GTEST_SHARD_INDEX", "GTEST_TOTAL_SHARDS"})

	// Set TEST_TMPDIR to /tmp, as some of the syscall tests require it to
	// be backed by tmpfs.
	env = filterEnv(env, []string{"TEST_TMPDIR"})
	env = append(env, fmt.Sprintf("TEST_TMPDIR=%s", testTmpDir))

	spec.Process.Env = env

	if *addUDSTree {
		cleanup, err := setupUDSTree(spec)
		if err != nil {
			t.Fatalf("error creating UDS tree: %v", err)
		}
		defer cleanup()
	}

	if err := runRunsc(tc, spec); err != nil {
		t.Errorf("test %q failed with error %v, want nil", tc.FullName(), err)
	}
}

// filterEnv returns an environment with the excluded variables removed.
func filterEnv(env, exclude []string) []string {
	var out []string
	for _, kv := range env {
		ok := true
		for _, k := range exclude {
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
				if *platform == "native" {
					// Run the test case on host.
					runTestCaseNative(testBin, tc, t)
				} else {
					// Run the test case in runsc.
					runTestCaseRunsc(testBin, tc, t)
				}
			},
		})
	}

	testing.Main(matchString, tests, nil, nil)
}
