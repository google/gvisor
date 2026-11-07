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

package systrap

import (
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/testutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

const childEnv = "SYSTRAP_TEST_CHILD"

func TestMain(m *testing.M) {
	switch mode := os.Getenv(childEnv); mode {
	case "", "hostmmio":
		cpuid.Initialize()
		os.Exit(m.Run())
	case "stuck":
		for {
			unix.Pause()
		}
	case "hoststall":
		if err := hostStallChild(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown %s: %q\n", childEnv, mode)
		os.Exit(1)
	}
}

// testMemoryManager implements the parts of platform.MemoryManager that
// platformContext.Switch touches on the syscall path. Syscall patching is
// disabled in the tests, so MMap and friends are never reached.
type testMemoryManager struct {
	usermem.IO // Never used.
	as         platform.AddressSpace
}

func (*testMemoryManager) MMap(pkgcontext.Context, memmap.MMapOpts) (hostarch.Addr, error) {
	panic("unexpected MMap call")
}

func (mm *testMemoryManager) AddressSpace() platform.AddressSpace { return mm.as }

func (*testMemoryManager) FindVMAByName(hostarch.AddrRange, string) (hostarch.Addr, uint64, error) {
	panic("unexpected FindVMAByName call")
}

const userCodeAddr = hostarch.Addr(0x100000)

// newSystrapTest creates a real Systrap instance, maps userCode into a new
// address space, and returns a context ready to Switch into it.
func newSystrapTest(t *testing.T) (*Systrap, platform.AddressSpace, *platformContext, *arch.Context64) {
	t.Helper()

	s, err := New(platform.Options{
		DisableSyscallPatching: true,
		// Only slow-path for now in order to not have to use a real
		// memory manager.
		DisableFastPath: true,
	})
	if err != nil {
		t.Fatalf("failed to create Systrap platform: %v", err)
	}

	as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatalf("failed to create address space: %v", err)
	}
	t.Cleanup(as.Release)

	fr, err := s.memoryFile.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("failed to allocate user code page: %v", err)
	}
	bs, err := s.memoryFile.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("failed to map user code page: %v", err)
	}
	if _, err := safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(testutil.UserCode))); err != nil {
		t.Fatalf("failed to write user code: %v", err)
	}
	if err := as.MapFile(userCodeAddr, s.memoryFile, fr, hostarch.AccessType{Read: true, Execute: true}, false); err != nil {
		t.Fatalf("failed to map user code into the stub address space: %v", err)
	}

	pctx := s.NewContext(pkgcontext.Background()).(*platformContext)
	t.Cleanup(pctx.Release)

	ac := arch.New(arch.Host)
	ac.SetIP(uintptr(userCodeAddr))
	return s, as, pctx, ac
}

// TestSwitchThreadIDVisibility runs a real Systrap instance and verifies
// that there is no window during which the ContextState indicates it's being
// worked on AND there is no thread currently working on it.
func TestSwitchThreadIDVisibility(t *testing.T) {
	_, as, pctx, ac := newSystrapTest(t)
	mm := &testMemoryManager{as: as}
	ctx := pkgcontext.Background()
	violations := atomic.Uint64{}
	stop := atomic.Bool{}
	samplerDone := make(chan struct{})
	startSampler := func(shared *sysmsg.ThreadContext) {
		go func() {
			defer close(samplerDone)
			for !stop.Load() {
				a1 := atomic.LoadUint64(&shared.AckedTime)

				// The stub ThreadID must always be set first,
				// and cleared last.
				tid := atomic.LoadUint32(&shared.ThreadID)
				state := shared.State.Get()

				a2 := atomic.LoadUint64(&shared.AckedTime)
				if a1 != 0 && a1 == a2 && state == sysmsg.ContextStateNone && tid == invalidThreadID {
					violations.Add(1)
				}
			}
		}()
	}

	for i := 0; i < 4000; i++ {
		si, _, err := pctx.Switch(ctx, mm, ac, 0)
		if err != nil {
			t.Fatalf("Switch failed at iteration %d: %v (si: %v)", i, err, si)
		}
		if sysno := ac.SyscallNo(); sysno != unix.SYS_GETPID {
			t.Fatalf("unexpected syscall %d at iteration %d", sysno, i)
		}
		ac.SetReturn(0) // Emulate the syscall return value.

		if i == 0 {
			startSampler(pctx.sharedContext.Load().shared)
		}
	}

	stop.Store(true)
	<-samplerDone
	if n := violations.Load(); n != 0 {
		t.Errorf("sampler observed %d acked contexts with an invalid ThreadID; "+
			"the stub published acked_time before ThreadID or cleared ThreadID "+
			"before publishing the context state", n)
	}
}

func TestSpinningQueueLayout(t *testing.T) {
	newSystrapTest(t)
	queueStart := stubContextQueueRegion + stubContextQueueRegionLen
	if stubSpinningThreadQueueAddr < queueStart || stubSpinningThreadQueueAddr+sysmsg.SpinningQueueMemSize > stubContextRegion {
		t.Errorf("spinning queue %#x not in [%#x, %#x)", stubSpinningThreadQueueAddr, queueStart, stubContextRegion)
	}
}

func TestHostMMIO(t *testing.T) {
	// A fresh process gives the source stub its own immutable ioctl policy.
	if os.Getenv(childEnv) != "hostmmio" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHostMMIO$")
		cmd.Env = append(os.Environ(), childEnv+"=hostmmio")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("HostMMIO child: %v\n%s", err, out)
		}
		return
	}
	p, err := New(platform.Options{
		HostMMIOIoctlRules: seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(unix.TIOCINQ)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(platform.Options{}); err == nil {
		t.Fatal("accepted a different process-global ioctl policy")
	}
	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := as.(*subprocess)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	var params [4]byte
	result, err := s.IoctlFlat(int32(r.Fd()), unix.TIOCINQ, params[:])
	if err != nil || result.Errno != 0 || hostarch.ByteOrder.Uint32(params[:]) != 3 {
		t.Fatalf("TIOCINQ: got %+v, %v, %v; want 3 bytes", result, err, params)
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if result, err := s.IoctlFlat(int32(null.Fd()), unix.TIOCINQ, params[:]); err != nil || result.Errno != unix.ENOTTY {
		t.Fatalf("TIOCINQ(/dev/null): got %+v, %v; want untrusted ENOTTY", result, err)
	}
	tid := s.syscallThread.thread.tid
	s.Release()
	if !s.dead.Load() {
		t.Fatal("device-bound address space was pooled instead of destroyed")
	}
	select {
	case <-s.requestsDone:
	default:
		t.Error("request goroutine remains running after Release")
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(int(tid), &status, unix.WALL|unix.WNOHANG, nil); err != unix.ECHILD {
		t.Errorf("syscall thread was not reaped: %v", err)
	}
}
