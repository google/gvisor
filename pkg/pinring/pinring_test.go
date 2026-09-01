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

package pinring

// This file verifies the Linux kernel behavior that the pin ring hack relies
// on; see the package comment.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// packetProbeEnv marks an invocation of this binary as an `AF_PACKET` probe
// child and selects its mode:
// - "true": pin the packet sockets into a disabled io_uring before exiting
// - "false": just hold the AF_PACKET sockets
// - "" or unset: Run the test as normal.
const packetProbeEnv = "AFPACKET_DEFERRED_RELEASE_PROBE"

// kvmProbeEnv is packetProbeEnv's equivalent for the KVM probe child, which
// holds bare KVM VM FDs instead of packet sockets.
const kvmProbeEnv = "KVM_DEFERRED_RELEASE_PROBE"

// Hold this many `AF_PACKET` sockets to amplify the effect of the deferred
// release.
const numSockets = 16

// Hold this many KVM VMs.
const numVMs = 4

// kvmCreateVM is _IO(KVMIO, 0x01) from <linux/kvm.h>.
// Importing the kvm platform package would create an import cycle.
const kvmCreateVM = 0xAE01

func TestMain(m *testing.M) {
	for env, probe := range map[string]func(bool){
		packetProbeEnv: packetProbe,
		kvmProbeEnv:    kvmProbe,
	} {
		v := os.Getenv(env)
		if v == "" {
			continue
		}
		deferRelease, err := strconv.ParseBool(v)
		if err != nil {
			fmt.Printf("%s=%q: %v\n", env, v, err)
			os.Exit(1)
		}
		probe(deferRelease)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// packetProbe executes when `AFPACKET_DEFERRED_RELEASE_PROBE` is set.
// It creates `AF_PACKET` sockets and exits without closing them.
// With deferRelease, the sockets are also registered as files of a
// permanently-disabled `io_uring` (as `PinRing` does), which should
// make the exit cheap at least as of this writing on Linux 6.18.
// A "SKIP: ..." line on stdout means the environment cannot run the probe
// and that the test should be skipped.
func packetProbe(deferRelease bool) {
	fds := make([]int32, numSockets)
	for i := range fds {
		sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
		if err == unix.EPERM || err == unix.EACCES {
			fmt.Printf("SKIP: creating an AF_PACKET socket requires CAP_NET_RAW: %v\n", err)
			return
		}
		if err != nil {
			fmt.Printf("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL): %v\n", err)
			os.Exit(1)
		}
		fds[i] = int32(sock)
	}
	if deferRelease {
		pinToRing(fds)
	}
	// `fds` being left open is very much intentional.
}

// kvmProbe is the same idea, but for bare KVM VM fds.
func kvmProbe(deferRelease bool) {
	kvmFD, err := unix.Open("/dev/kvm", unix.O_RDWR, 0)
	if err == unix.ENOENT || err == unix.EACCES || err == unix.EPERM {
		fmt.Printf("SKIP: cannot open /dev/kvm: %v\n", err)
		return
	}
	if err != nil {
		fmt.Printf("open(/dev/kvm): %v\n", err)
		os.Exit(1)
	}
	fds := make([]int32, numVMs)
	for i := range fds {
		vm, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(kvmFD), kvmCreateVM, 0)
		if errno == unix.EPERM || errno == unix.EACCES {
			fmt.Printf("SKIP: cannot create a KVM VM: %v\n", errno)
			return
		}
		if errno != 0 {
			fmt.Printf("ioctl(KVM_CREATE_VM): %v\n", errno)
			os.Exit(1)
		}
		fds[i] = int32(vm)
	}
	if deferRelease {
		pinToRing(fds)
	}
	// `fds` being left open is, again, very much intentional.
}

// pinnedRing holds pinToRing's ring open until the probe's `do_exit`.
// This is necessary because go GC would otherwise auto-close the FD if
// it sees a dangling `*os.File`.
var pinnedRing *os.File

// pinToRing parks `fds` in the fixed-file table of a new permanently
// disabled io_uring, which is deliberately left open for `do_exit` to drop.
// Prints "SKIP: ..." and returns if the environment has no usable io_uring.
func pinToRing(fds []int32) {
	ring, err := NewDisabledIOURing()
	switch {
	case err == nil:
	case errors.Is(err, unix.ENOSYS):
		fmt.Println("SKIP: kernel doesn't support io_uring (ENOSYS)")
		return
	case errors.Is(err, unix.EPERM):
		fmt.Println("SKIP: kernel has io_uring disabled (EPERM)")
		return
	case errors.Is(err, unix.EINVAL):
		fmt.Println("SKIP: kernel doesn't understand IORING_SETUP_R_DISABLED (EINVAL)")
		return
	default:
		fmt.Println(err)
		os.Exit(1)
	}
	pinnedRing = ring
	if err := registerFiles(int(ring.Fd()), fds); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// TestAFPacketDeferredRelease compares the exit time of children processes
// holding AF_PACKET sockets with and without the io_uring pin hack.
func TestAFPacketDeferredRelease(t *testing.T) {
	compareProbes(t, packetProbeEnv, "AF_PACKET socket")
}

// TestKVMVMDeferredRelease is TestAFPacketDeferredRelease for KVM VM fds.
func TestKVMVMDeferredRelease(t *testing.T) {
	compareProbes(t, kvmProbeEnv, "KVM VM fd")
}

// compareProbes runs the probe child and checks that we do gain time by
// using the pinring hack to release FDs early.
func compareProbes(t *testing.T, env, what string) {
	expedited, err := os.ReadFile("/sys/kernel/rcu_expedited")
	if err != nil {
		t.Fatalf("cannot read rcu_expedited: %v", err)
	}
	if strings.TrimSpace(string(expedited)) != "0" {
		t.Skip("rcu_expedited is set; a normal grace period cannot be observed")
	}

	// One warm run to warm up every page of the binary and check if we
	// need to skip.
	out, _, err := runProbe(env, true)
	if err != nil {
		t.Fatalf("warmup probe: %v\noutput: %s", err, out)
	}
	if strings.HasPrefix(out, "SKIP: ") {
		t.Skip(strings.TrimSuffix(strings.TrimPrefix(out, "SKIP: "), "\n"))
	}

	var plain, deferred []time.Duration
	for range 32 {
		plain = append(plain, timeProbe(t, env, false))
		deferred = append(deferred, timeProbe(t, env, true))
	}
	p50Plain, p50Deferred := median(plain), median(deferred)
	t.Logf("p50: plain=%v, with deferral=%v", p50Plain, p50Deferred)

	if p50Plain < p50Deferred {
		t.Errorf("pinning the %s did not help with latency: plain exit p50 = %v vs deferred exit p50 = %v", what, p50Plain, p50Deferred)
	}
}

func runProbe(env string, deferRelease bool) (string, time.Duration, error) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), env+"="+strconv.FormatBool(deferRelease))
	start := time.Now()
	out, err := cmd.CombinedOutput()
	return string(out), time.Since(start), err
}

func timeProbe(t *testing.T, env string, deferRelease bool) time.Duration {
	t.Helper()
	out, d, err := runProbe(env, deferRelease)
	if err != nil || out != "" {
		t.Fatalf("probe(%s=%t): %v\noutput: %s", env, deferRelease, err, out)
	}
	return d
}

func median(samples []time.Duration) time.Duration {
	s := slices.Clone(samples)
	slices.Sort(s)
	return (s[(len(s)-1)/2] + s[len(s)/2]) / 2
}
