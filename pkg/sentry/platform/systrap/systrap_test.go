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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/pool"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/testutil"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestMain(m *testing.M) {
	cpuid.Initialize()
	os.Exit(m.Run())
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

func TestUVMOperationsRejectInvalidDevice(t *testing.T) {
	var stub *subprocess
	t.Cleanup(func() {
		if stub != nil && stub.alive() {
			t.Error("UVM-bound address space remained available for recycling")
		}
	})
	_, as, _, _ := newSystrapTest(t)
	stub = as.(*subprocess)
	initializer := as.(platform.UVMAddressSpace)
	if _, err := initializer.UVMInitialize(-1, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("UVMInitialize(-1) returned %v, want EBADF", err)
	}
	if _, err := initializer.UVMPopulatePageable(-1, 0, hostarch.PageSize, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("UVMPopulatePageable(-1) returned %v, want EBADF", err)
	}
	if _, err := initializer.UVMSetPreferredLocation(-1, 0, hostarch.PageSize, [16]byte{}, -1); !errors.Is(err, unix.EBADF) {
		t.Fatalf("UVMSetPreferredLocation(-1) returned %v, want EBADF", err)
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("opening /dev/null: %v", err)
	}
	defer f.Close()
	if _, err := initializer.UVMInitialize(int32(f.Fd()), 0); !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("UVMInitialize(/dev/null) returned %v, want ENOTTY", err)
	}
	if _, err := initializer.UVMPopulatePageable(int32(f.Fd()), 0, hostarch.PageSize, 0); !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("UVMPopulatePageable(/dev/null) returned %v, want ENOTTY", err)
	}
	if _, err := initializer.UVMSetPreferredLocation(int32(f.Fd()), 0, hostarch.PageSize, [16]byte{}, -1); !errors.Is(err, unix.ENOTTY) {
		t.Fatalf("UVMSetPreferredLocation(/dev/null) returned %v, want ENOTTY", err)
	}
	if !as.(*subprocess).uvmInitialized.Load() {
		t.Error("address space may be recycled after a UVM initialization attempt")
	}
}

func TestUVMRejectsAddressSpaceAfterThreadCreationFailure(t *testing.T) {
	_, as, _, _ := newSystrapTest(t)
	stub := as.(*subprocess)
	stub.markSysmsgThreadCreationFailed()
	// This test marks a healthy mm without leaving any failed clone or stack
	// mapping behind, so it can safely return to the pool during cleanup.
	t.Cleanup(func() {
		stub.syscallThreadMu.Lock()
		stub.uvmUnsafe = false
		stub.syscallThreadMu.Unlock()
	})
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("opening /dev/null: %v", err)
	}
	defer f.Close()
	if _, err := stub.UVMInitialize(int32(f.Fd()), 0); !errors.Is(err, unix.EIO) {
		t.Fatalf("UVMInitialize after failed thread creation returned %v, want EIO", err)
	}
	if stub.uvmInitialized.Load() {
		t.Error("unsafe address space was bound to UVM")
	}
}

func TestUVMThreadCreationFailureDoesNotRecycleStack(t *testing.T) {
	for _, missingClone := range []bool{false, true} {
		t.Run(fmt.Sprintf("missingClone=%t", missingClone), func(t *testing.T) {
			s := &subprocess{
				requests:        make(chan any, 1),
				sysmsgStackPool: pool.Pool{Start: 0, Limit: 1},
			}
			id, ok := s.sysmsgStackPool.Get()
			if !ok {
				t.Fatal("failed to allocate stack ID")
			}
			s.uvmInitialized.Store(true)
			go func() {
				req := (<-s.requests).(requestThread)
				if missingClone {
					req.thread <- nil
					return
				}
				req.thread <- &thread{tgid: 1 << 30, tid: 1 << 30, sysmsgStackID: id}
			}()
			defer func() {
				if msg, ok := recover().(string); !ok || !strings.Contains(msg, "UVM address space") {
					t.Errorf("failed thread creation did not fail closed: %v", msg)
				}
				if _, ok := s.sysmsgStackPool.Get(); ok {
					t.Error("failed UVM clone's stack ID was recycled")
				}
			}()
			if err := s.createSysmsgThread(); err != nil {
				t.Errorf("failed thread creation returned %v instead of failing closed", err)
			}
		})
	}
}

func TestUVMAddressSpaceCleanup(t *testing.T) {
	s, _, _, _ := newSystrapTest(t)
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("opening /dev/null: %v", err)
	}
	defer f.Close()
	for i := 0; i < 8; i++ {
		as, err := s.NewAddressSpace(platform.AddressSpaceOptions{})
		if err != nil {
			t.Fatalf("iteration %d: NewAddressSpace: %v", i, err)
		}
		stub := as.(*subprocess)
		tids := []int{int(stub.syscallThread.thread.tid)}
		for _, p := range stub.sysmsgThreads {
			tids = append(tids, int(p.thread.tid))
		}
		if _, err := stub.UVMInitialize(int32(f.Fd()), 0); !errors.Is(err, unix.ENOTTY) {
			t.Fatalf("iteration %d: UVMInitialize(/dev/null): %v", i, err)
		}
		as.Release()
		if !stub.dead.Load() || stub.contextQueue != nil || stub.threadContextRegion != 0 || stub.syscallThread.sentryAddr != 0 || len(stub.sysmsgThreads) != 0 {
			t.Fatalf("iteration %d: released address space retains shared mappings", i)
		}
		if stub.contextQueueRange.Length() != 0 || stub.threadContextRange.Length() != 0 || stub.syscallThread.stackRange.Length() != 0 {
			t.Fatalf("iteration %d: released address space retains memory-file allocations", i)
		}
		select {
		case <-stub.requestsDone:
		default:
			t.Fatalf("iteration %d: request goroutine remains running", i)
		}
		for _, tid := range tids {
			var status unix.WaitStatus
			if _, err := unix.Wait4(tid, &status, unix.WALL|unix.WNOHANG, nil); err != unix.ECHILD {
				t.Fatalf("iteration %d: thread %d was not reaped: %v", i, tid, err)
			}
		}
	}
}

func TestUVMAddressSpaceUnexpectedDeath(t *testing.T) {
	for name, operation := range map[string]func(*subprocess){
		"kill":    (*subprocess).kill,
		"release": (*subprocess).Release,
		"unmap":   func(s *subprocess) { s.Unmap(0, hostarch.PageSize) },
	} {
		t.Run(name, func(t *testing.T) {
			s := &subprocess{}
			s.uvmInitialized.Store(true)
			if name != "kill" {
				s.dead.Store(true)
			}
			defer func() {
				if msg, ok := recover().(string); !ok || !strings.Contains(msg, "UVM address space") {
					t.Errorf("unexpected death did not fail closed: %v", msg)
				}
			}()
			operation(s)
		})
	}
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
