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
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

const childEnv = "SYSTRAP_TEST_CHILD"

func TestMain(m *testing.M) {
	switch mode := os.Getenv(childEnv); mode {
	case "":
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

	fr, err := s.memoryFile.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.System})
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

func TestCreateInitialSysmsgThreadDiscardsUnstartedSubprocess(t *testing.T) {
	s, err := New(platform.Options{DisableSyscallPatching: true, DisableFastPath: true})
	if err != nil {
		t.Fatalf("failed to create Systrap platform: %v", err)
	}
	if s.memoryFile != globalPool.source.memoryFile {
		t.Cleanup(s.memoryFile.Destroy)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	stub, err := globalPool.source.createStub()
	if err != nil {
		t.Fatalf("createStub: %v", err)
	}
	sp := &subprocess{
		requests:        make(chan any),
		memoryFile:      s.memoryFile,
		sysmsgStackPool: pool.Pool{Start: 0, Limit: 1},
	}
	if err := sp.initSyscallThread(stub, true); err != nil {
		t.Fatalf("initSyscallThread: %v", err)
	}
	sp.unmap()
	queueFR, contextFR := sp.mapSharedRegions()
	notify := sp.syscallThread.seccompNotify
	mappings := [...]struct {
		addr uintptr
		fr   memmap.FileRange
	}{
		{reflect.ValueOf(sp.contextQueue).Pointer(), queueFR},
		{sp.threadContextRegion, contextFR},
		{sp.syscallThread.sentryAddr, sp.syscallThread.stackRange},
	}
	for _, m := range mappings {
		s.memoryFile.IncRef(m.fr, 0)
		defer s.memoryFile.DecRef(m.fr)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(s.memoryFile.FD()), &stat); err != nil {
		t.Fatalf("fstat memory file: %v", err)
	}
	device := fmt.Sprintf("%02x:%02x", unix.Major(stat.Dev), unix.Minor(stat.Dev))
	inode := strconv.FormatUint(stat.Ino, 10)
	checkMappings := func(wantMapped bool) {
		t.Helper()
		data, err := os.ReadFile("/proc/self/maps")
		if err != nil {
			t.Fatalf("read /proc/self/maps: %v", err)
		}
		var found [len(mappings)]bool
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 || fields[3] != device || fields[4] != inode {
				continue
			}
			first, last, _ := strings.Cut(fields[0], "-")
			start, startErr := strconv.ParseUint(first, 16, 64)
			end, endErr := strconv.ParseUint(last, 16, 64)
			offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
			if startErr != nil || endErr != nil || offsetErr != nil {
				t.Fatalf("invalid mapping in /proc/self/maps: %q", line)
			}
			for i, m := range mappings {
				addr := uint64(m.addr)
				overlap := max(start, addr)
				if overlap < min(end, addr+m.fr.Length()) && offset+(overlap-start) == m.fr.Start+(overlap-addr) {
					found[i] = true
				}
			}
		}
		for i, m := range mappings {
			if found[i] != wantMapped {
				t.Errorf("memory file mapping at %#x present = %t, want %t", m.addr, found[i], wantMapped)
			}
		}
	}
	checkMappings(true)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		req := (<-sp.requests).(requestThread)
		sp.syscallThreadMu.Lock()
		sendPtraceSyscallRequestResult(req, threadResult{err: rejectedSysmsgClone(unix.EAGAIN)})
		sp.syscallThreadMu.Unlock()
		sp.servePtraceSyscallRequests()
	}()

	if err := sp.createInitialSysmsgThread(queueFR, contextFR); err != unix.EAGAIN {
		t.Errorf("createInitialSysmsgThread got %v, want %v", err, unix.EAGAIN)
	}

	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Error("ptrace request worker did not exit")
	}
	if pid, err := unix.Wait4(int(stub.tid), nil, unix.WALL|unix.WNOHANG, nil); err != unix.ECHILD {
		t.Errorf("Wait4 after discarding stub got (%d, %v), want ECHILD", pid, err)
	}
	if notify != nil {
		if _, err := notify.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("seccomp notification FD after discarding stub: %v, want %v", err, os.ErrClosed)
		}
	}
	checkMappings(false)
	for _, m := range mappings {
		if !s.memoryFile.HasUniqueRef(m.fr) {
			t.Errorf("discarded stub retained a reference to %v", m.fr)
		}
	}
}
