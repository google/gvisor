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

package boot

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	runtimedebug "runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/gccontrol"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/capabilitytest"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	fsgofer "gvisor.dev/gvisor/runsc/gofer/fs"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

func init() {
	log.SetLevel(log.Debug)
	if err := fsgofer.OpenProcSelfFD("/proc/self/fd"); err != nil {
		panic(err)
	}
}

func testConfig() *config.Config {
	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(testFlags)
	conf, err := config.NewFromFlags(testFlags)
	if err != nil {
		panic(err)
	}
	// Change test defaults.
	conf.RootDir = "unused_root_dir"
	conf.Network = config.NetworkNone
	conf.DisableSeccomp = true
	return conf
}

// testSpec returns a simple spec that can be used in tests.
func testSpec() *specs.Spec {
	return &specs.Spec{
		// The host filesystem root is the sandbox root.
		Root: &specs.Root{
			Path:     "/",
			Readonly: true,
		},
		Process: &specs.Process{
			Args: []string{"/bin/true"},
		},
	}
}

// startGofer starts a new gofer routine serving 'root' path. It returns the
// sandbox side of the connection, and a function that when called will stop the
// gofer.
func startGofer(root string, conf *config.Config) (int, func(), error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, nil, err
	}
	sandboxEnd, goferEnd := fds[0], fds[1]

	socket, err := unet.NewSocket(goferEnd)
	if err != nil {
		unix.Close(sandboxEnd)
		unix.Close(goferEnd)
		return 0, nil, fmt.Errorf("error creating server on FD %d: %v", goferEnd, err)
	}
	server := lisafs.NewServer()
	connImpl := fsgofer.NewConnectionImpl(&fsgofer.Config{
		HostUDS:            conf.GetHostUDS(),
		HostFifo:           conf.HostFifo,
		DonateMountPointFD: conf.DirectFS,
	})
	c, err := server.CreateConnection(socket, root, fsgofer.ConnectionOpts(true), connImpl)
	if err != nil {
		return 0, nil, err
	}
	server.StartConnection(c)
	// Closing the gofer socket will stop the gofer and exit goroutine above.
	cleanup := func() {
		if err := socket.Close(); err != nil {
			log.Warningf("Error closing gofer socket: %v", err)
		}
		server.Wait()
		server.Destroy()
	}
	return sandboxEnd, cleanup, nil
}

func createLoader(conf *config.Config, spec *specs.Spec) (*Loader, func(), error) {
	l, cleanup, err := createLoaderWithDefaultFreeOSMemory(conf, spec)
	if err != nil {
		return nil, nil, err
	}
	// Stub background idle heap releases so short tests do not call
	// gccontrol.MaybeFreeOSMemory after Destroy into later tests.
	l.freeOSMemory = func() {}
	return l, cleanup, nil
}

func createLoaderWithDefaultFreeOSMemory(conf *config.Config, spec *specs.Spec) (*Loader, func(), error) {
	sock := fmt.Sprintf("\x00loader-test.%010d", rand.Int())
	fd, err := server.CreateSocket(sock)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create socket: %w", err)
	}
	sandEnd, cleanup, err := startGofer(spec.Root.Path, conf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start gofer: %w", err)
	}

	// Loader takes ownership of stdio.
	var stdio []int
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		fd := int(f.Fd())
		newFd, err := unix.Dup(fd)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to dup FD %d: %w", fd, err)
		}
		stdio = append(stdio, newFd)
	}

	args := Args{
		ID:               "foo",
		Spec:             spec,
		Conf:             conf,
		ControllerFD:     fd,
		GoferFDs:         []int{sandEnd},
		DevGoferFD:       -1,
		StdioFDs:         stdio,
		GoferMountConfs:  []specutils.GoferMountConf{{Lower: specutils.Lisafs, Upper: specutils.NoOverlay}},
		PodInitConfigFD:  -1,
		ExecFD:           -1,
		RootfsUpperTarFD: -1,
		CPUDMALatencyFD:  -1,
	}
	l, err := New(args)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("boot.New: %w", err)
	}
	return l, cleanup, nil
}

// TestRun runs a simple application in a sandbox and checks that it succeeds.
func TestRun(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}

	defer l.Destroy()
	defer cleanup()

	// Start a goroutine to read the start chan result, otherwise Run will
	// block forever.
	var resultChanErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		resultChanErr = <-l.ctrl.manager.startResultChan
		wg.Done()
	}()

	// Run the container.
	if err := l.Run(); err != nil {
		t.Errorf("error running container: %v", err)
	}

	// We should have not gotten an error on the startResultChan.
	wg.Wait()
	if resultChanErr != nil {
		t.Errorf("error on startResultChan: %v", resultChanErr)
	}

	// Wait for the application to exit.  It should succeed.
	if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
		t.Errorf("application exited with %s, want exit status 0", status)
	}
}

// TestStartSignal tests that the controller Start message will cause
// WaitForStartSignal to return.
func TestStartSignal(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer l.ctrl.srv.Stop(time.Hour)

	// Start a goroutine that calls WaitForStartSignal and writes to a
	// channel when it returns.
	waitFinished := make(chan struct{})
	go func() {
		l.WaitForStartSignal()
		// Pretend that Run() executed and returned no error.
		l.ctrl.manager.startResultChan <- nil
		waitFinished <- struct{}{}
	}()

	// Nothing has been written to the channel, so waitFinished should not
	// return.  Give it a little bit of time to make sure the goroutine has
	// started.
	select {
	case <-waitFinished:
		t.Errorf("WaitForStartSignal completed but it should not have")
	case <-time.After(50 * time.Millisecond):
		// OK.
	}

	// Trigger the control server StartRoot method.
	startArgs := sentryapi.StartArgs{
		CID:         "foo",
		MemoryLimit: gccontrol.NoMemoryLimit,
	}
	if err := l.ctrl.manager.StartRoot(&startArgs, nil); err != nil {
		t.Errorf("error calling StartRoot: %v", err)
	}

	// Now WaitForStartSignal should return (within a short amount of
	// time).
	select {
	case <-waitFinished:
		// OK.
	case <-time.After(50 * time.Millisecond):
		t.Errorf("WaitForStartSignal did not complete but it should have")
	}
}

// TestRestoreFailBeforeStart checks that a restore that fails before it starts
// restoring reports the failure.
func TestRestoreFailBeforeStart(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	if err := l.ctrl.manager.Restore(&sentryapi.RestoreOpts{}, nil); err == nil {
		t.Fatalf("restoring without files succeeded")
	}
	if err := l.waitRestore(); err == nil {
		t.Errorf("waiting for the failed restore succeeded")
	}
}

// watchStartupHeapReleases replaces l.freeOSMemory. It returns a channel that
// receives a value for each release.
func watchStartupHeapReleases(l *Loader) <-chan struct{} {
	released := make(chan struct{}, 10)
	l.freeOSMemory = func() { released <- struct{}{} }
	return released
}

// expectOneStartupHeapRelease checks that exactly one release happens.
func expectOneStartupHeapRelease(t *testing.T, released <-chan struct{}) {
	t.Helper()
	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatalf("startup heap was not released")
	}
	select {
	case <-released:
		t.Errorf("startup heap was released more than once")
	case <-time.After(2 * startupHeapReleaseIdleDelay):
	}
}

// TestStartupHeapReleaseOnStart checks that the startup heap is released once
// after the root container starts.
func TestStartupHeapReleaseOnStart(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	released := watchStartupHeapReleases(l)

	go func() { <-l.ctrl.manager.startResultChan }()
	if err := l.Run(); err != nil {
		t.Fatalf("error running container: %v", err)
	}
	expectOneStartupHeapRelease(t, released)
	if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
		t.Errorf("application exited with %s, want exit status 0", status)
	}
}

// TestStartupHeapReleaseOnRestore checks that the startup heap is released
// once after a restore is complete.
func TestStartupHeapReleaseOnRestore(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()
	released := watchStartupHeapReleases(l)
	defer l.ctrl.srv.Stop(time.Hour)

	// Put the loader in the state that a restore leaves it in after the
	// restored kernel starts (see containerManager.Restore and Loader.run).
	l.mu.Lock()
	l.state = restoringStarted
	l.mu.Unlock()
	l.ctrl.manager.onRestoreDone(sentryapi.Savings{})
	// A second trigger while the release is pending doesn't add a release.
	l.releaseStartupHeapWhenIdle()
	expectOneStartupHeapRelease(t, released)
}

func TestStartupGC(t *testing.T) {
	const (
		gcDisabled       = -1
		defaultGCPercent = 100
		queryMemoryLimit = -1
	)
	gcPercent := func() int {
		sample := [1]metrics.Sample{{Name: "/gc/gogc:percent"}}
		metrics.Read(sample[:])
		if sample[0].Value.Uint64() == math.MaxUint64 {
			return gcDisabled
		}
		return int(int32(sample[0].Value.Uint64()))
	}
	resetRuntimeGC := func(t *testing.T) {
		t.Helper()
		gccontrol.MaybeFreeOSMemory()
		origPercent := runtimedebug.SetGCPercent(defaultGCPercent)
		origLimit := runtimedebug.SetMemoryLimit(math.MaxInt64)
		t.Cleanup(func() {
			gccontrol.MaybeFreeOSMemory()
			runtimedebug.SetGCPercent(origPercent)
			runtimedebug.SetMemoryLimit(origLimit)
		})
	}

	t.Run("runResumesOnIdleRelease", func(t *testing.T) {
		resetRuntimeGC(t)
		bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
		if bootGCSuspension == nil {
			t.Fatal("gccontrol.Suspend returned nil")
		}
		defer bootGCSuspension.End()
		bootGCSuspension.EndAfter(time.Hour)

		l, cleanup, err := createLoaderWithDefaultFreeOSMemory(testConfig(), testSpec())
		if err != nil {
			t.Fatalf("createLoaderWithDefaultFreeOSMemory: %v", err)
		}
		defer l.Destroy()
		defer cleanup()

		origFree := l.freeOSMemory
		gotAfterRelease := make(chan int, 1)
		l.freeOSMemory = func() {
			origFree()
			gotAfterRelease <- gcPercent()
		}

		go func() { <-l.ctrl.manager.startResultChan }()
		if err := l.Run(); err != nil {
			t.Fatalf("l.Run(): %v", err)
		}
		if got := <-gotAfterRelease; got != defaultGCPercent {
			t.Fatalf("GCPercent after idle freeOSMemory = %d, want %d", got, defaultGCPercent)
		}
		if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
			t.Errorf("application exited with %s, want exit status 0", status)
		}
	})

	t.Run("runResumesAfterStartupGCDelay", func(t *testing.T) {
		resetRuntimeGC(t)
		origDelay := startupGCResumeDelay
		startupGCResumeDelay = 20 * time.Millisecond
		t.Cleanup(func() { startupGCResumeDelay = origDelay })

		l, cleanup, err := createLoader(testConfig(), testSpec())
		if err != nil {
			t.Fatalf("createLoader: %v", err)
		}
		defer l.Destroy()
		defer cleanup()
		released := watchStartupHeapReleases(l)

		bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
		if bootGCSuspension == nil {
			t.Fatal("gccontrol.Suspend returned nil")
		}
		defer bootGCSuspension.End()
		bootGCSuspension.EndAfter(5 * time.Millisecond)

		go func() { <-l.ctrl.manager.startResultChan }()
		if err := l.Run(); err != nil {
			t.Fatalf("l.Run(): %v", err)
		}
		if got := gcPercent(); got != gcDisabled {
			t.Fatalf("GCPercent right after l.Run() = %d, want %d", got, gcDisabled)
		}
		deadline := time.Now().Add(2 * time.Second)
		resumed := false
		for time.Now().Before(deadline) {
			if runtimedebug.SetMemoryLimit(queryMemoryLimit) == math.MaxInt64 && gcPercent() == defaultGCPercent {
				resumed = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !resumed {
			t.Fatal("GC remained suspended past startupGCResumeDelay")
		}
		<-released
		if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
			t.Errorf("application exited with %s, want exit status 0", status)
		}
	})

	t.Run("resumesOnCreatedRunError", func(t *testing.T) {
		resetRuntimeGC(t)
		bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
		if bootGCSuspension == nil {
			t.Fatal("gccontrol.Suspend returned nil")
		}
		defer bootGCSuspension.End()
		bootGCSuspension.EndAfter(time.Hour)

		l, cleanup, err := createLoader(testConfig(), testSpec())
		if err != nil {
			t.Fatalf("createLoader: %v", err)
		}
		defer l.Destroy()
		defer cleanup()
		defer l.ctrl.srv.Stop(time.Hour)

		l.mu.Lock()
		l.networkArgs = &sentryapi.CreateLinksAndRoutesArgs{
			FDBasedLinks: []sentryapi.FDBasedLink{{}},
			XDPLinks:     []sentryapi.XDPLink{{}},
		}
		l.mu.Unlock()
		if err := l.run(); err == nil {
			t.Fatal("l.run() with conflicting network links succeeded")
		}
		if got := gcPercent(); got != defaultGCPercent {
			t.Fatalf("GCPercent after failed created run = %d, want %d", got, defaultGCPercent)
		}
	})

	t.Run("postRestoreResumesOnIdleRelease", func(t *testing.T) {
		resetRuntimeGC(t)
		l, cleanup, err := createLoaderWithDefaultFreeOSMemory(testConfig(), testSpec())
		if err != nil {
			t.Fatalf("createLoaderWithDefaultFreeOSMemory: %v", err)
		}
		defer l.Destroy()
		defer cleanup()
		defer l.ctrl.srv.Stop(time.Hour)

		origFree := l.freeOSMemory
		gotAfterRelease := make(chan int, 1)
		l.freeOSMemory = func() {
			origFree()
			gotAfterRelease <- gcPercent()
		}

		restoreGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
		if restoreGCSuspension == nil {
			t.Fatal("gccontrol.Suspend returned nil")
		}
		defer restoreGCSuspension.End()
		restoreGCSuspension.EndAfter(time.Hour)

		l.mu.Lock()
		l.state = restoringStarted
		l.mu.Unlock()
		l.ctrl.manager.onRestoreDone(sentryapi.Savings{})
		if got := <-gotAfterRelease; got != defaultGCPercent {
			t.Fatalf("GCPercent after post-restore freeOSMemory = %d, want %d", got, defaultGCPercent)
		}
	})

	t.Run("multiContainerRestoreClampsBeforeSubcontainers", func(t *testing.T) {
		resetRuntimeGC(t)
		bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
		if bootGCSuspension == nil {
			t.Fatal("gccontrol.Suspend returned nil")
		}
		defer bootGCSuspension.End()
		bootGCSuspension.EndAfter(time.Hour)

		const (
			savedMFBytes = 128 << 20
			rootLimit    = 512 << 20
			higherLimit  = 1024 << 20
		)
		r := &restorer{
			totalContainers:      3,
			savedMemoryFileBytes: savedMFBytes,
		}
		started, err := r.restoreContainerInfo(nil, &containerInfo{cid: "root", containerName: "root"}, rootLimit)
		if err != nil || started {
			t.Fatalf("restoreContainerInfo(root) = (%v, %v), want (false, nil)", started, err)
		}
		const wantSoftLimit = int64((rootLimit - savedMFBytes) / 2)
		if got := runtimedebug.SetMemoryLimit(queryMemoryLimit); got != wantSoftLimit {
			t.Fatalf("MemoryLimit after container 1/3 = %d, want %d", got, wantSoftLimit)
		}
		if started, err := r.restoreContainerInfo(nil, &containerInfo{cid: "sub1", containerName: "sub1"}, higherLimit); err != nil || started {
			t.Fatalf("restoreContainerInfo(sub1) = (%v, %v), want (false, nil)", started, err)
		}
		if r.memoryLimit != rootLimit {
			t.Fatalf("r.memoryLimit = %d, want %d", r.memoryLimit, rootLimit)
		}

		// Tight headroom on a pending container resumes Boot's GC
		// suspension early.
		rTight := &restorer{
			totalContainers:      2,
			savedMemoryFileBytes: savedMFBytes,
		}
		if started, err := rTight.restoreContainerInfo(nil, &containerInfo{cid: "root", containerName: "root"}, savedMFBytes); err != nil || started {
			t.Fatalf("restoreContainerInfo(tight) = (%v, %v), want (false, nil)", started, err)
		}
		if got := gcPercent(); got != defaultGCPercent {
			t.Fatalf("GCPercent after tight container 1/2 = %d, want %d", got, defaultGCPercent)
		}
	})

	t.Run("startRootClampsBootLimit", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			memoryLimit uint64
			wantPercent int
			wantLimit   int64
		}{
			{
				name:        "loweredLimit",
				memoryLimit: 384 << 20,
				wantPercent: gcDisabled,
				wantLimit:   192 << 20,
			},
			{
				name:        "unknownLimitResumesBootGC",
				memoryLimit: 0,
				wantPercent: defaultGCPercent,
				wantLimit:   math.MaxInt64,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resetRuntimeGC(t)
				bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
				if bootGCSuspension == nil {
					t.Fatal("gccontrol.Suspend returned nil")
				}
				defer bootGCSuspension.End()
				bootGCSuspension.EndAfter(time.Hour)

				l, cleanup, err := createLoader(testConfig(), testSpec())
				if err != nil {
					t.Fatalf("createLoader: %v", err)
				}
				defer l.Destroy()
				defer cleanup()
				released := watchStartupHeapReleases(l)

				runDone := make(chan error, 1)
				go func() {
					l.WaitForStartSignal()
					runDone <- l.Run()
				}()

				startArgs := sentryapi.StartArgs{
					CID:         "foo",
					MemoryLimit: tc.memoryLimit,
				}
				if err := l.ctrl.manager.StartRoot(&startArgs, nil); err != nil {
					t.Fatalf("StartRoot: %v", err)
				}
				if err := <-runDone; err != nil {
					t.Fatalf("l.Run(): %v", err)
				}
				if got := gcPercent(); got != tc.wantPercent {
					t.Fatalf("GCPercent = %d, want %d", got, tc.wantPercent)
				}
				if got := runtimedebug.SetMemoryLimit(queryMemoryLimit); got != tc.wantLimit {
					t.Fatalf("MemoryLimit = %d, want %d", got, tc.wantLimit)
				}
				<-released
				if status := l.WaitExit(); !status.Exited() || status.ExitStatus() != 0 {
					t.Errorf("application exited with %s, want exit status 0", status)
				}
			})
		}
	})

	t.Run("saveOptsFromSpecOmitsMemoryLimit", func(t *testing.T) {
		opts, err := saveOptsFromSpec(testSpec(), nil, false /* useCheckpointGofer */)
		if err != nil {
			t.Fatalf("saveOptsFromSpec: %v", err)
		}
		if opts.MemoryLimit != 0 {
			t.Fatalf("saveOptsFromSpec().MemoryLimit = %d, want 0", opts.MemoryLimit)
		}
	})

	t.Run("restoreClampsBootLimitFromStatefile", func(t *testing.T) {
		const savedMFBytes = 256 << 20
		specsStr, err := specutils.ConvertSpecsToString(map[string]*specs.Spec{
			"foo": testSpec(),
			"sub": testSpec(),
		})
		if err != nil {
			t.Fatalf("ConvertSpecsToString: %v", err)
		}
		statePath := filepath.Join(t.TempDir(), "state.img")
		sf, err := os.Create(statePath)
		if err != nil {
			t.Fatalf("os.Create: %v", err)
		}
		sw, err := statefile.NewWriter(sf, nil, map[string]string{
			ContainerCountKey:               "2",
			ContainerSpecsKey:               specsStr,
			VersionKey:                      version.Version(),
			"gvisor_memory_file_used_bytes": strconv.FormatUint(savedMFBytes, 10),
		})
		if err != nil {
			sf.Close()
			t.Fatalf("statefile.NewWriter: %v", err)
		}
		if err := sw.Close(); err != nil {
			t.Fatalf("statefile.Writer.Close: %v", err)
		}

		for _, tc := range []struct {
			name        string
			memoryLimit uint64
			wantPercent int
			wantLimit   int64
		}{
			{
				name:        "loweredLimitSubtractsSavedMemoryFile",
				memoryLimit: 640 << 20,
				wantPercent: gcDisabled,
				wantLimit:   (640<<20 - savedMFBytes) / 2,
			},
			{
				name:        "unknownLimitResumesBootGC",
				memoryLimit: 0,
				wantPercent: defaultGCPercent,
				wantLimit:   math.MaxInt64,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resetRuntimeGC(t)
				bootGCSuspension := gccontrol.Suspend(gccontrol.NoMemoryLimit, 0)
				if bootGCSuspension == nil {
					t.Fatal("boot Suspend returned nil")
				}
				defer bootGCSuspension.End()
				bootGCSuspension.EndAfter(time.Hour)

				l, cleanup, err := createLoader(testConfig(), testSpec())
				if err != nil {
					t.Fatalf("createLoader: %v", err)
				}
				defer func() {
					if r := l.ctrl.manager.restorer; r != nil {
						if r.stateFile != nil {
							_ = r.stateFile.Close()
						}
						if r.mainMF != nil {
							r.mainMF.Destroy()
						}
						l.k.Unpause()
					}
					l.Destroy()
					cleanup()
				}()

				rf, err := os.Open(statePath)
				if err != nil {
					t.Fatalf("os.Open: %v", err)
				}
				defer rf.Close()

				var reply sentryapi.RestoreReply
				opts := sentryapi.RestoreOpts{
					FilePayload: urpc.FilePayload{Files: []*os.File{rf}},
					MemoryLimit: tc.memoryLimit,
				}
				if err := l.ctrl.manager.Restore(&opts, &reply); err != nil {
					t.Fatalf("Restore: %v", err)
				}
				if got := gcPercent(); got != tc.wantPercent {
					t.Fatalf("GCPercent = %d, want %d", got, tc.wantPercent)
				}
				if got := runtimedebug.SetMemoryLimit(queryMemoryLimit); got != tc.wantLimit {
					t.Fatalf("MemoryLimit = %d, want %d", got, tc.wantLimit)
				}
			})
		}
	})
}

// Test that network=host with raw sockets enabled requires CAP_NET_RAW on the
// host.
func TestHostnetWithRawSockets(t *testing.T) {
	capabilitytest.DropEffective(t, unix.CAP_NET_RAW)

	// Configure host network with raw sockets.
	conf := testConfig()
	conf.Network = config.NetworkHost
	conf.EnableRaw = true

	// Creating loader should fail.
	l, err := New(Args{
		ID:              "should-fail",
		Spec:            testSpec(),
		Conf:            conf,
		DevGoferFD:      -1,
		PodInitConfigFD: -1,
		ExecFD:          -1,
		CPUDMALatencyFD: -1,
	})
	if err == nil {
		l.Destroy()
		t.Fatalf("expected loader.New() to fail but it did not")
	}
	// Error message must be about CAP_NET_RAW.
	if !strings.Contains(err.Error(), "CAP_NET_RAW") {
		t.Errorf("expected error to contain CAP_NET_RAW but got %q", err)
	}
}

type CreateMountTestcase struct {
	name string
	// Spec that will be used to create the mount manager.  Note
	// that we can't mount procfs without a kernel, so each spec
	// MUST contain something other than procfs mounted at /proc.
	spec specs.Spec
	// Paths that are expected to exist in the resulting fs.
	expectedPaths []string
}

func createMountTestcases() []*CreateMountTestcase {
	testCases := []*CreateMountTestcase{
		{
			// Only proc.
			name: "only proc mount",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /proc, /dev, and /sys should always be mounted.
			expectedPaths: []string{"/proc", "/dev", "/sys"},
		},
		{
			// Mount at a deep path, with many components that do
			// not exist in the root.
			name: "deep mount path",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/some/very/very/deep/path",
						Type:        "tmpfs",
					},
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			},
			// /some/deep/path should be mounted, along with /proc, /dev, and /sys.
			expectedPaths: []string{"/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			// Mounts are nested inside each other.
			name: "nested mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/qux",
						Type:        "tmpfs",
					},
					{
						// File mounts with the same prefix.
						Destination: "/foo/qux-quz",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/foo/bar/baz",
						Type:        "tmpfs",
					},
					{
						// A deep path that is in foo but not the other mounts.
						Destination: "/foo/some/very/very/deep/path",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/foo", "/foo/bar", "/foo/bar/baz", "/foo/qux",
				"/foo/qux-quz", "/foo/some/very/very/deep/path", "/proc", "/dev", "/sys"},
		},
		{
			name: "mount inside /dev",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev",
						Type:        "tmpfs",
					},
					{
						// Mount with the same prefix.
						Destination: "/dev/fd-foo",
						Type:        "tmpfs",
					},
					{
						// Unsupported fs type.
						Destination: "/dev/mqueue",
						Type:        "mqueue",
					},
					{
						Destination: "/dev/foo",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev/bar",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/dev", "/dev/fd-foo", "/dev/foo", "/dev/bar", "/sys"},
		},
		{
			name: "mounts inside mandatory mounts",
			spec: specs.Spec{
				Root: &specs.Root{
					Path:     os.TempDir(),
					Readonly: true,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
					{
						Destination: "/sys/bar",
						Type:        "tmpfs",
					},
					{
						Destination: "/tmp/baz",
						Type:        "tmpfs",
					},
					{
						Destination: "/dev/goo",
						Type:        "tmpfs",
					},
				},
			},
			expectedPaths: []string{"/proc", "/sys", "/sys/bar", "/tmp", "/tmp/baz", "/dev/goo"},
		},
	}

	return testCases
}

// Test that MountNamespace can be created with various specs.
func TestCreateMountNamespace(t *testing.T) {
	for _, tc := range createMountTestcases() {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			spec.Mounts = tc.spec.Mounts
			spec.Root = tc.spec.Root

			t.Logf("Using root: %q", spec.Root.Path)
			l, loaderCleanup, err := createLoader(testConfig(), spec)
			if err != nil {
				t.Fatalf("failed to create loader: %v", err)
			}
			defer l.Destroy()
			defer loaderCleanup()

			l.mu.Lock()
			defer l.mu.Unlock()
			mntr := l.newContainerMounter(&l.root)
			ctx := l.k.SupervisorContext()
			creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
			mns, err := mntr.mountAll(ctx, creds, l.root.spec, l.root.conf, &l.root.procArgs)
			if err != nil {
				t.Fatalf("mountAll: %v", err)
			}

			root := mns.Root(ctx)
			defer root.DecRef(ctx)
			for _, p := range tc.expectedPaths {
				target := &vfs.PathOperation{
					Root:  root,
					Start: root,
					Path:  fspath.Parse(p),
				}

				if d, err := l.k.VFS().GetDentryAt(ctx, l.root.procArgs.Credentials, target, &vfs.GetDentryOptions{}); err != nil {
					t.Errorf("expected path %v to exist with spec %v, but got error %v", p, tc.spec, err)
				} else {
					d.DecRef(ctx)
				}
			}
		})
	}
}

type createMountPointTestCase struct {
	name string
	path string
	mode linux.FileMode
	fail bool
}

func TestCreateMountPoint(t *testing.T) {
	createMountPointTestCases := []createMountPointTestCase{
		{
			name: "File",
			path: "/test/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "Directory",
			path: "/test/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "FileWithIntDirs",
			path: "/test/a/b/c/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "DirectoryWithIntDirs",
			path: "/test/d/e/f/g/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "ExistingFile",
			path: "/test/test-file",
			mode: linux.ModeRegular,
		},
		{
			name: "ExistingDirectory",
			path: "/test/test-dir",
			mode: linux.ModeDirectory,
		},
		{
			name: "DirVSFile",
			path: "/test/test-file",
			mode: linux.ModeDirectory,
			fail: true,
		},
		{
			name: "FileVSDir",
			path: "/test/test-dir",
			mode: linux.ModeRegular,
			fail: true,
		},
	}

	spec := testSpec()
	spec.Root = &specs.Root{
		Path: os.TempDir(),
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Destination: "/test",
		Type:        "tmpfs",
	})

	t.Logf("Using root: %q", spec.Root.Path)
	l, loaderCleanup, err := createLoader(testConfig(), spec)
	if err != nil {
		t.Fatalf("failed to create loader: %v", err)
	}
	defer l.Destroy()
	defer loaderCleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	mntr := l.newContainerMounter(&l.root)
	ctx := l.k.SupervisorContext()
	creds := auth.NewRootCredentials(l.root.procArgs.Credentials.UserNamespace)
	mns, err := mntr.mountAll(ctx, creds, l.root.spec, l.root.conf, &l.root.procArgs)
	if err != nil {
		t.Fatalf("mountAll: %v", err)
	}

	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	for _, tc := range createMountPointTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := mntr.makeMountPoint(ctx, creds, mns, tc.path, tc.mode); err != nil {
				if tc.fail {
					return
				}
				t.Fatalf("makeMountPoint failed: %v", err)
			} else {
				if tc.fail {
					t.Fatalf("makeMountPoint doesn't fail")
				}
			}
			target := &vfs.PathOperation{
				Root:  root,
				Start: root,
				Path:  fspath.Parse(tc.path),
			}

			if mode, err := mntr.getPathMode(ctx, creds, target); err != nil {
				t.Errorf("expected path %v, but got error %v", tc.path, err)
			} else {
				if mode.IsDir() != tc.mode.IsDir() {
					t.Errorf("path mode %v doesn't match the mount mode %v", mode, tc.mode)
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	cpuid.Initialize()
	os.Exit(m.Run())
}

func TestNetworkConfig(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("error creating loader: %v", err)
	}
	defer l.Destroy()
	defer cleanup()

	// We aren't going to wait on this application, so the control server
	// needs to be shut down manually.
	defer l.ctrl.srv.Stop(time.Hour)

	go func() {
		l.WaitForStartSignal()
		l.ctrl.manager.startResultChan <- nil
	}()

	args := &sentryapi.CreateLinksAndRoutesArgs{
		LoopbackLinks: []sentryapi.LoopbackLink{
			{
				Name: "lo",
				Addresses: []sentryapi.IPWithPrefix{
					{Address: net.IP("\x7f\x00\x00\x01"), PrefixLen: 8},
				},
				Routes: []sentryapi.Route{
					{
						Destination: net.IPNet{
							IP:   net.IP{127, 0, 0, 0},
							Mask: net.IPMask{255, 0, 0, 0},
						},
					},
				},
			},
		},
	}
	if err := l.ctrl.manager.SetNetworkArgs(args, nil); err != nil {
		t.Errorf("error calling SetNetworkConfig: %v", err)
	}
	var networkArgs sentryapi.CreateLinksAndRoutesArgs
	if err := l.ctrl.manager.GetNetworkConfig(nil, &networkArgs); err != nil {
		t.Errorf("error calling NetworkConfig: %v", err)
	}
	if diff := cmp.Diff(networkArgs.LoopbackLinks, args.LoopbackLinks); diff != "" {
		t.Errorf("Network config content mismatch (-want +got):\n%s", diff)
	}
}

func TestSignalUnkillablePolicyMapping(t *testing.T) {
	for _, tc := range []struct {
		confPolicy   config.SignalUnkillablePolicy
		kernelPolicy kernel.SignalUnkillablePolicy
	}{
		{config.SignalUnkillableNone, kernel.SignalUnkillableNone},
		{config.SignalUnkillableLinux, kernel.SignalUnkillableLinux},
		{config.SignalUnkillablePolicy(-1), kernel.SignalUnkillableNone},
	} {
		if got := signalUnkillablePolicy(tc.confPolicy); got != tc.kernelPolicy {
			t.Errorf("signalUnkillablePolicy(%v) = %v, want %v", tc.confPolicy, got, tc.kernelPolicy)
		}
	}
}
