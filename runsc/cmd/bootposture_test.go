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

package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/sandboxposture"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/specutils"
)

// This test checks the security posture of the `runsc boot` process.
// This includes process credentials, capabilities, namespaces, chroot,
// file descriptors, seccomp state, etc.

const postureFDLimit = 4096

type postureCase struct {
	name           string
	directfs       bool
	network        config.NetworkType
	extraFDClasses []string

	// platform overrides the gVisor platform; leave empty to use the default.
	platform string

	// fdLimit, when non-zero, is passed as --fdlimit.
	fdLimit int
}

// TestBootPosture checks the Sentry process (`runsc boot`)'s security posture.
func TestBootPosture(t *testing.T) {
	if sync.RaceEnabled {
		t.Skip("Skipping test when running with race detector (gotsan); dynamically linked binary cannot re-exec in minimal chroot")
	}
	if missing := sandboxposture.UnsupportedFeatures(); len(missing) > 0 {
		t.Skipf("This kernel cannot report %s, so a collected posture would not be exhaustive", strings.Join(missing, ", "))
	}
	for _, tc := range []postureCase{
		{name: "default", directfs: true, network: config.NetworkSandbox},
		{name: "hostinet", directfs: true, network: config.NetworkHost},
		{name: "no_directfs", directfs: false, network: config.NetworkSandbox},
		{name: "no_directfs_hostinet", directfs: false, network: config.NetworkHost},
		{name: "kvm", directfs: true, network: config.NetworkSandbox, platform: "kvm", extraFDClasses: sandboxposture.KVMFDClasses()},
		{name: "fdlimit", directfs: true, network: config.NetworkSandbox, fdLimit: postureFDLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testBootPosture(t, tc)
		})
	}
}

func testBootPosture(t *testing.T, tc postureCase) {
	t.Helper()
	if uid := os.Getuid(); uid != 0 {
		t.Skipf("Test is running as UID %d; this test requires root", uid)
	}

	if tc.platform == "kvm" {
		f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			t.Skipf("Cannot open /dev/kvm, so the KVM platform cannot run here: %v", err)
		}
		f.Close()
	}
	isHostNetwork := tc.network == config.NetworkHost

	conf := testutil.TestConfig(t)
	conf.DirectFS = tc.directfs
	conf.Network = tc.network
	if tc.platform != "" {
		conf.Platform = tc.platform
	}
	if tc.fdLimit != 0 {
		conf.FDLimit = tc.fdLimit
	}
	// testutil.TestConfig sets this so that tests can run without privileges.
	// Undo it here since we do want to test the non-test case.
	conf.TestOnlyAllowRunAsCurrentUserWithoutChroot = false
	// Ignore cgroups as this requires further privileges
	// `test/root/cgroup_test.go` already tests its correctness.
	conf.IgnoreCgroups = true

	if isHostNetwork && !ownNetNS {
		t.Skip("This process has no network namespace of its own; a host-network sandbox cannot be checked from it")
	}

	if !tc.directfs {
		// We need the `nobody` user to be mapped in our userns for the
		// non-DirectFS case.
		mapped, err := sandboxposture.UserNamespaceMapsID(65534)
		if err != nil {
			t.Fatalf("Checking whether UID 65534 is mapped: %v", err)
		}
		if !mapped {
			t.Skip("UID 65534 is not mapped in this user namespace")
		}
		// Check if `runsc` is runnable by `nobody`.
		reachable, err := sandboxposture.ExecutableByOthers(specutils.ExePath)
		if err != nil {
			t.Fatalf("Checking whether %q is reachable by an unprivileged user: %v", specutils.ExePath, err)
		}
		if !reachable {
			t.Fatalf("%q cannot be executed by an unprivileged user, so the sandbox cannot exec it as nobody", specutils.ExePath)
		}
	}

	stop := testutil.StartReaper()
	defer stop()

	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("Error setting up container: %v", err)
	}
	defer cleanup()

	c, err := container.New(conf, container.Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("Error creating container: %v", err)
	}
	defer c.Destroy()

	ref, err := sandboxposture.SelfReference()
	if err != nil {
		t.Fatalf("Error describing the reference process: %v", err)
	}
	opts := sandboxposture.ExpectedOpts{
		DirectFS:             tc.directfs,
		NetworkMode:          tc.network.String(),
		EnableRaw:            conf.EnableRaw,
		RequiresCapSysPtrace: sandboxposture.PlatformCapSysPtrace[conf.Platform],
		GoDebug:              sandboxposture.PlatformGoDebug[conf.Platform],
		ExtraFDClasses:       tc.extraFDClasses,
		CgoEnabled:           config.CgoEnabled,
		// We call container.New directly below, so we are the sandbox parent
		// (unlike when the containerd shim is in the middle).
		ChildOfRef: true,
		MEMLOCK:    ref.Limits["MEMLOCK"],
		Ref:        ref,
	}
	if tc.fdLimit != 0 {
		nofile := fmt.Sprintf("%d/%d", tc.fdLimit, tc.fdLimit)
		if ref.Limits["NOFILE"] == nofile {
			nofile = sandboxposture.LimitSameAsRef
		}
		opts.NOFILE = nofile
	}

	pid := c.Sandbox.Getpid()
	if err := c.Start(conf); err != nil {
		t.Fatalf("Error starting container: %v", err)
	}
	goferPid := c.GoferPid.Load()
	t.Run("sentry", func(t *testing.T) {
		if got := c.Sandbox.Getpid(); got != pid {
			t.Errorf("Sandbox PID changed from %d to %d across start", pid, got)
		}
		got, err := sandboxposture.Collect(sandboxposture.Opts{PID: pid, RefPID: os.Getpid()})
		if err != nil {
			t.Fatalf("Error collecting posture of sandbox %d: %v", pid, err)
		}
		if d := sandboxposture.Diff(sandboxposture.Expected(opts), got); d != "" {
			t.Errorf("Sandbox %d: %s", pid, d)
		}
	})
	t.Run("gofer", func(t *testing.T) {
		if err := checkProcessCaps(goferPid, goferCaps); err != nil {
			t.Errorf("Gofer capabilities: %v", err)
		}
	})
}

// ownNetNS is whether this process has a network namespace of its own.
// See `TestMain` and `runInOwnNetNS`.
var ownNetNS bool

// ownNetNSEnv is set when `runInOwnNetNS` has re-exec'd.
const ownNetNSEnv = "RUNSC_CMD_TEST_OWN_NETNS"

// runInOwnNetNS re-executes the test binary in a dedicated netns to avoid
// flakiness when starting subcontainers from the test process which may or
// may not inherit the calling thread's netns, depending on which host thread
// actually ends up doing the syscall.
func runInOwnNetNS() bool {
	if os.Getenv(ownNetNSEnv) == "1" {
		return true
	}
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNET,
		Pdeathsig:  unix.SIGKILL,
	}
	cmd.Env = append(os.Environ(), ownNetNSEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			os.Exit(code)
		}
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot re-execute test in a new netns: %v\n", err)
		return false
	}
	os.Exit(0)
	panic("unreachable")
}
