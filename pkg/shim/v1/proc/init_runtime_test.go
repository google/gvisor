// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/protobuf/types"
	"github.com/containerd/containerd/v2/pkg/stdio"
	runc "github.com/containerd/go-runc"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func BenchmarkRuntimeLockUncontended(b *testing.B) {
	p := New("bench", nil, stdio.Stdio{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, unlock, err := p.lockRuntime(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		unlock()
	}
}

func BenchmarkRuntimeLockContended(b *testing.B) {
	p := New("bench", nil, stdio.Stdio{})
	b.SetParallelism(8)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, unlock, err := p.lockRuntime(context.Background())
			if err != nil {
				b.Error(err)
				return
			}
			time.Sleep(time.Microsecond)
			unlock()
		}
	})
}

func BenchmarkRuntimeLockBurst(b *testing.B) {
	p := New("bench", nil, stdio.Stdio{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, release, err := p.lockRuntime(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		var ready, finished sync.WaitGroup
		ready.Add(32)
		finished.Add(32)
		for j := 0; j < 32; j++ {
			go func() {
				defer finished.Done()
				ready.Done()
				_, unlock, err := p.lockRuntime(context.Background())
				if err != nil {
					b.Error(err)
					return
				}
				unlock()
			}()
		}
		ready.Wait()
		time.Sleep(time.Millisecond)
		release()
		finished.Wait()
	}
}

func TestRuntimeLockCancellationHandoff(t *testing.T) {
	p := New("test", nil, stdio.Stdio{})
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		p.mu.Lock()
		result := make(chan error, 1)
		go func() {
			result <- p.RuntimeCall(ctx, func(context.Context, *runsccmd.Runsc) error {
				return errors.New("canceled operation entered runtime")
			})
		}()
		cancel()
		p.mu.Unlock()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: canceled operation returned %v", i, err)
		}
		retryCtx, retryCancel := context.WithTimeout(context.Background(), time.Second)
		err := p.RuntimeCall(retryCtx, func(context.Context, *runsccmd.Runsc) error { return nil })
		retryCancel()
		if err != nil {
			t.Fatalf("iteration %d: cancellation lost the lock permit: %v", i, err)
		}
	}
}

func testPidfd(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL) {
		t.Skipf("pidfd unavailable: %v", err)
	}
	if err != nil {
		t.Fatalf("pidfd_open: %v", err)
	}
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("pidfd signals unavailable: %v", err)
		}
		t.Fatalf("pidfd_send_signal: %v", err)
	}
	return fd
}

type testProcessMonitor struct{}

func (testProcessMonitor) Subscribe() chan runc.Exit  { return make(chan runc.Exit) }
func (testProcessMonitor) Unsubscribe(chan runc.Exit) {}

func newRuntimeWedgedInit(t *testing.T) *Init {
	t.Helper()
	old, oldLong := runscTimeout, runscLongOperationTimeout
	runscTimeout = 200 * time.Millisecond
	runscLongOperationTimeout = runscTimeout
	t.Cleanup(func() { runscTimeout, runscLongOperationTimeout = old, oldLong })
	fake := filepath.Join(t.TempDir(), "fake-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatalf("write fake runsc: %v", err)
	}
	p := New("test", &runsccmd.Runsc{Command: fake, Root: t.TempDir()}, stdio.Stdio{})
	p.initState = &runningState{p: p}
	return p
}

func requireBounded(t *testing.T, start time.Time) {
	t.Helper()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("operation returned after %v, want under 2s", elapsed)
	}
}

func TestRuntimeCallsAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Init) error
	}{
		{"Status", func(p *Init) error { _, err := p.Status(context.Background()); return err }},
		{"Stats", func(p *Init) error { _, err := p.Stats(context.Background(), "test"); return err }},
		{"Kill", func(p *Init) error { return p.Kill(context.Background(), uint32(unix.SIGTERM), false) }},
		{"Update", func(p *Init) error { return p.Update(context.Background(), &types.Any{Value: []byte(`{}`)}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			start := time.Now()
			if err := tc.call(p); err == nil {
				t.Fatalf("%s succeeded against a wedged runsc", tc.name)
			}
			requireBounded(t, start)
		})
	}
}

func TestCreateWedgedRunscIsBounded(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Bundle = t.TempDir()
	t.Cleanup(p.closeIO)
	start := time.Now()
	if err := p.Create(context.Background(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err == nil {
		t.Fatal("Create succeeded against a wedged runsc")
	}
	requireBounded(t, start)
}

func init() {
	if os.Getenv("GVISOR_SHIM_TEST_RUNTIME_HELPER") == "1" {
		if filepath.Base(os.Args[0]) == "runsc-sandbox" {
			gate := os.NewFile(3, "sandbox-gate")
			token := make([]byte, 1)
			if _, err := gate.Read(token); err == nil && token[0] == 'E' {
				path, err := exec.LookPath("sleep")
				if err != nil || unix.Exec(path, []string{"sleep", "60"}, os.Environ()) != nil {
					os.Exit(2)
				}
			}
			_ = gate.Close()
		}
		os.Exit(0)
	}
}

func sandboxIdentityProcess(t *testing.T, bundle, executable string) (*exec.Cmd, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command(executable, "--bundle="+bundle)
	if executable == "/bin/sh" {
		process = exec.Command("/bin/sh", "-c", "read token <&3", "--bundle="+bundle)
	}
	process.Args[0] = "runsc-sandbox"
	process.ExtraFiles = []*os.File{r}
	if err := process.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatal(err)
	}
	r.Close()
	t.Cleanup(func() {
		_ = w.Close()
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	return process, w
}

func TestCreatePinsOnlyMatchingSandbox(t *testing.T) {
	t.Setenv("GVISOR_SHIM_TEST_RUNTIME_HELPER", "1")
	probe := testPidfd(t, os.Getpid())
	_ = unix.Close(probe)
	for _, name := range []string{"Matching", "MatchingSymlink", "MatchingPATH", "MatchingBundleSymlink", "MatchingBundleTrailingSlash", "MatchingBundleRelative", "WrongBundle", "UnrelatedProcess", "SpoofedExecutable", "FailedIO", "Sidecar", "PluginSidecar", "OverrideSidecar", "LinkedSidecar", "WrongSidecar"} {
		t.Run(name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			runscLongOperationTimeout = 5 * time.Second
			p.Sandbox = true
			p.Platform = fakePlatform{}
			p.Bundle = t.TempDir()
			t.Cleanup(p.closeIO)
			t.Cleanup(p.closeSandboxPidfd)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			p.runtime.Command = exe
			processExe := exe
			bundle := p.Bundle
			switch name {
			case "MatchingBundleSymlink":
				bundle = filepath.Join(t.TempDir(), "bundle-link")
				if err := os.Symlink(p.Bundle, bundle); err != nil {
					t.Fatal(err)
				}
			case "MatchingBundleTrailingSlash":
				bundle += "/"
			case "MatchingBundleRelative":
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				bundle, err = filepath.Rel(cwd, bundle)
				if err != nil {
					t.Fatal(err)
				}
			}
			if name == "WrongBundle" {
				bundle = t.TempDir()
			}
			if name == "SpoofedExecutable" {
				processExe = "/bin/sh"
			}
			if strings.HasSuffix(name, "Sidecar") {
				payload, err := os.ReadFile(exe)
				if err != nil {
					t.Fatal(err)
				}
				cli := filepath.Join(t.TempDir(), "runsc")
				if err := os.WriteFile(cli, payload, 0o755); err != nil {
					t.Fatal(err)
				}
				p.runtime.Command = cli
				dir := filepath.Join(filepath.Dir(cli), "gvisor-bin")
				if name == "OverrideSidecar" {
					dir = t.TempDir()
					t.Setenv("GVISOR_SIDECAR_BINARIES_DIR", dir)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				sentryName := "gvisor_sentry"
				if name == "PluginSidecar" {
					sentryName = "gvisor_sentry_plugin_stack"
				}
				processExe = filepath.Join(dir, sentryName)
				if err := os.WriteFile(processExe, payload, 0o755); err != nil {
					t.Fatal(err)
				}
				if name == "WrongSidecar" {
					processExe = filepath.Join(t.TempDir(), sentryName)
					if err := os.WriteFile(processExe, payload, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				if name == "LinkedSidecar" {
					link := filepath.Join(t.TempDir(), "runsc")
					if err := os.Symlink(cli, link); err != nil {
						t.Fatal(err)
					}
					p.runtime.Command = link
				}
			}
			if name == "MatchingSymlink" || name == "MatchingPATH" {
				link := filepath.Join(t.TempDir(), "runsc")
				if err := os.Symlink(exe, link); err != nil {
					t.Fatal(err)
				}
				p.runtime.Command = link
				if name == "MatchingPATH" {
					t.Setenv("PATH", filepath.Dir(link)+":"+os.Getenv("PATH"))
					p.runtime.Command = "runsc"
				}
			}
			process, _ := sandboxIdentityProcess(t, bundle, processExe)
			pid := process.Process.Pid
			if name == "UnrelatedProcess" {
				pid = os.Getpid()
			}
			if err := os.WriteFile(filepath.Join(p.Bundle, "init.pid"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := &CreateConfig{ID: p.id, Bundle: p.Bundle}
			if name == "FailedIO" {
				cfg.Stdin = filepath.Join(t.TempDir(), "missing-fifo")
			}
			err = p.Create(context.Background(), cfg)
			if name == "FailedIO" {
				if err == nil {
					t.Fatal("Create succeeded with missing stdin FIFO")
				}
			} else if err != nil {
				t.Fatalf("Create: %v", err)
			}
			want := strings.HasPrefix(name, "Matching") || strings.HasSuffix(name, "Sidecar") && name != "WrongSidecar"
			if got := p.sandboxPidfd >= 0; got != want {
				t.Fatalf("Create retained pidfd = %v, want %v", got, want)
			}
		})
	}
}

func TestPinnedSandboxRemainsOwnedAcrossExec(t *testing.T) {
	t.Setenv("GVISOR_SHIM_TEST_RUNTIME_HELPER", "1")
	p := newRuntimeWedgedInit(t)
	runscLongOperationTimeout = 5 * time.Second
	wedgedCommand := p.runtime.Command
	p.Sandbox = true
	p.Bundle = t.TempDir()
	p.Platform = fakePlatform{}
	t.Cleanup(p.closeIO)
	t.Cleanup(p.closeSandboxPidfd)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sandbox, gate := sandboxIdentityProcess(t, p.Bundle, exe)
	if err := os.WriteFile(filepath.Join(p.Bundle, "init.pid"), []byte(strconv.Itoa(sandbox.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = exe
	if err := p.Create(context.Background(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
		t.Fatal(err)
	}
	if p.sandboxPidfd < 0 {
		t.Fatal("Create did not retain the matching sandbox pidfd")
	}
	neighbor := exec.Command("sleep", "60")
	if err := neighbor.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = neighbor.Process.Kill(); _ = neighbor.Wait() })
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	sleepExe, err := os.Stat(sleepPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Write([]byte{'E'}); err != nil {
		t.Fatal(err)
	}
	changed := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", p.pid))
		if err == nil && os.SameFile(sleepExe, actual) {
			changed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !changed {
		t.Fatal("sandbox did not exec sleep with its original PID")
	}
	poll := []unix.PollFd{{Fd: int32(p.sandboxPidfd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatalf("pidfd lost the live sandbox across exec: %d, %v", n, err)
	}
	p.runtime.Command = wedgedCommand
	if err := p.Kill(context.Background(), uint32(unix.SIGKILL), true); err == nil {
		t.Fatal("Kill succeeded against wedged runsc")
	}
	done := make(chan error, 1)
	go func() { done <- sandbox.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("explicit sandbox SIGKILL failed to terminate its pinned sandbox after exec")
	}
	if err := neighbor.Process.Signal(unix.Signal(0)); err != nil {
		t.Fatalf("neighbor was affected by sandbox teardown: %v", err)
	}
}

func TestFuseStatusRetryPreservesOutcome(t *testing.T) {
	for _, name := range []string{"Stopped", "Error", "Running"} {
		t.Run(name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			runscTimeout = 3 * time.Second
			p.FuseAbort = true
			result := "echo '{\"status\":\"running\"}'"
			switch name {
			case "Stopped":
				result = "echo 'does not exist' >&2; exit 1"
			case "Error":
				result = "echo 'unexpected state failure' >&2; exit 1"
			}
			flag := filepath.Join(t.TempDir(), "first-call")
			script := "#!/bin/sh\nif [ ! -e '" + flag + "' ]; then : > '" + flag + "'; exec >/dev/null 2>&1; exec sleep 60; fi\n" + result + "\n"
			if err := os.WriteFile(p.runtime.Command, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			status, err := p.Status(context.Background())
			if name == "Error" {
				if err == nil || !strings.Contains(err.Error(), "unexpected state failure") {
					t.Fatalf("Status = %q, %v, want retry error", status, err)
				}
			} else {
				want := statusRunning
				if name == "Stopped" {
					want = statusStopped
				}
				if err != nil || status != want {
					t.Fatalf("Status = %q, %v, want %q", status, err, want)
				}
			}
		})
	}
}

func TestExecRuntimeCallsAreBounded(t *testing.T) {
	for _, name := range []string{"Start", "Kill"} {
		t.Run(name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.Monitor = testProcessMonitor{}
			e := &execProcess{parent: p, path: t.TempDir(), id: "exec", internalPid: 1, waitBlock: make(chan struct{})}
			e.execState = &execCreatedState{p: e}
			start := time.Now()
			var err error
			if name == "Start" {
				err = e.Start(context.Background())
			} else {
				err = e.Kill(context.Background(), uint32(unix.SIGKILL), true)
			}
			if err == nil {
				t.Fatalf("exec %s succeeded against a wedged runsc", name)
			}
			requireBounded(t, start)
			_ = e.delete(context.Background())
		})
	}
}

func TestExecCanceledCallerDoesNotWaitBehindLock(t *testing.T) {
	e := &execProcess{}
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func(context.Context) error{e.Start, e.Delete, func(ctx context.Context) error {
		return e.Kill(ctx, uint32(unix.SIGKILL), true)
	}} {
		start := time.Now()
		if err := call(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("exec error = %v, want cancellation", err)
		}
		requireBounded(t, start)
	}
}

func TestExecDeleteBoundsIOWaitAndCanRetry(t *testing.T) {
	_ = newRuntimeWedgedInit(t)
	e := &execProcess{}
	e.execState = &execStoppedState{p: e}
	e.wg.Add(1)
	start := time.Now()
	err := e.Delete(context.Background())
	e.wg.Done()
	if !errors.Is(err, errRunscTimeout) {
		t.Fatalf("Delete error = %v, want shim timeout", err)
	}
	requireBounded(t, start)
	if err := e.Delete(context.Background()); err != nil {
		t.Fatalf("Delete retry: %v", err)
	}
}

func TestDeleteClosesPidfdBeforeFailedUnmount(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Sandbox = true
	p.sandboxPidfd = testPidfd(t, os.Getpid())
	t.Cleanup(p.closeSandboxPidfd)
	p.initState = &stoppedState{process: p}
	fake := filepath.Join(t.TempDir(), "successful-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = fake
	old := unmountRootfs
	unmountRootfs = func(string, int) error { return unix.EBUSY }
	t.Cleanup(func() { unmountRootfs = old })
	if err := p.Delete(context.Background()); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("Delete error = %v, want unmount failure", err)
	}
	if p.sandboxPidfd != -1 {
		t.Fatal("successful runtime deletion retained its pidfd")
	}
}

func TestInitDeleteBoundsIOWaitAndCanRetry(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Sandbox = true
	_, pipe := pinnedTestProcess(t, p)
	oldUnmount := unmountRootfs
	unmountRootfs = func(string, int) error { return nil }
	t.Cleanup(func() { unmountRootfs = oldUnmount })
	p.initState = &stoppedState{process: p}
	fake := filepath.Join(t.TempDir(), "successful-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = fake
	p.io = &closerIO{}
	p.wg.Add(1)
	releaseIO := sync.OnceFunc(p.wg.Done)
	t.Cleanup(releaseIO)
	start := time.Now()
	if err := p.Delete(context.Background()); !errors.Is(err, errRunscTimeout) {
		t.Fatalf("Delete error = %v, want shim timeout", err)
	}
	requireBounded(t, start)
	if !p.io.(*closerIO).closed {
		t.Fatal("timed-out Delete did not close IO")
	}
	requireLiveProcess(t, pipe)
	releaseIO()
	if err := p.Delete(context.Background()); err != nil {
		t.Fatalf("Delete retry: %v", err)
	}
	if _, ok := p.initState.(*deletedState); !ok {
		t.Fatalf("Delete retry left state %T", p.initState)
	}
}

func TestInitCallsObserveCancellationWhileLocked(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		call func(context.Context) error
	}{
		{"Status", func(ctx context.Context) error { _, err := p.Status(ctx); return err }},
		{"Stats", func(ctx context.Context) error { _, err := p.Stats(ctx, p.id); return err }},
		{"Update", func(ctx context.Context) error { return p.Update(ctx, nil) }},
		{"Start", p.Start},
		{"Restore", func(ctx context.Context) error { return p.Restore(ctx, &extension.RestoreConfig{}) }},
		{"Checkpoint", func(ctx context.Context) error { return p.CheckpointSandbox(ctx, nil) }},
		{"Delete", p.Delete},
		{"Kill", func(ctx context.Context) error { return p.Kill(ctx, uint32(unix.SIGKILL), true) }},
		{"Exec", func(ctx context.Context) error { _, err := p.Exec(ctx, "", nil); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			if err := tc.call(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
			requireBounded(t, start)
		})
	}
}

func TestRuntimeDeadlineIncludesLockWait(t *testing.T) {
	p := New("lock-wait", nil, stdio.Stdio{})
	mu := &p.mu
	mu.Lock()
	start := time.Now()
	timer := time.AfterFunc(50*time.Millisecond, mu.Unlock)
	defer timer.Stop()
	ctx, unlock, err := lockRuntimeFor(mu, context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(start.Add(time.Second+20*time.Millisecond)) {
		t.Fatalf("runtime deadline = %v, want lock wait included", deadline)
	}
}

func pinnedTestProcess(t *testing.T, p *Init) (*exec.Cmd, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command("sleep", "60")
	process.ExtraFiles = []*os.File{w}
	if err := process.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
		_ = r.Close()
		p.closeSandboxPidfd()
	})
	p.sandboxPidfd = testPidfd(t, process.Process.Pid)
	return process, r
}

func requireLiveProcess(t *testing.T, r *os.File) {
	t.Helper()
	if err := r.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := r.Read(buf[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("process lost its pipe (possibly a zombie): %v", err)
	}
}

func TestExplicitSandboxKillAfterFuseWatchdog(t *testing.T) {
	for _, callerDeadline := range []bool{false, true} {
		name := "ShimDeadline"
		if callerDeadline {
			name = "CallerDeadline"
		}
		t.Run(name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			runscTimeout = 2 * time.Second
			p.Sandbox = true
			p.FuseAbort = true
			_, pipe := pinnedTestProcess(t, p)
			neighbor := New("neighbor", nil, stdio.Stdio{})
			_, neighborPipe := pinnedTestProcess(t, neighbor)
			ctx := context.Background()
			wantCause := errRunscTimeout
			if callerDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 1200*time.Millisecond)
				defer cancel()
				wantCause = context.DeadlineExceeded
			}
			start := time.Now()
			if err := p.Kill(ctx, uint32(unix.SIGKILL), true); !errors.Is(err, wantCause) {
				t.Fatalf("Kill error = %v, want %v after failed FUSE abort", err, wantCause)
			}
			if elapsed := time.Since(start); elapsed < time.Second || elapsed > 4*time.Second {
				t.Fatalf("Kill returned after %v, want FUSE watchdog followed by runtime deadline", elapsed)
			}
			if callerDeadline {
				requireLiveProcess(t, pipe)
			} else {
				if err := pipe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var buf [1]byte
				if _, err := pipe.Read(buf[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("sandbox survived failed FUSE abort and explicit SIGKILL --all: %v", err)
				}
			}
			requireLiveProcess(t, neighborPipe)
		})
	}
}

func TestSandboxExitClosesDeadPidfd(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Sandbox = true
	p.Platform = fakePlatform{}
	sandbox, _ := pinnedTestProcess(t, p)
	neighbor := New("neighbor", nil, stdio.Stdio{})
	_, neighborPipe := pinnedTestProcess(t, neighbor)
	fd := p.sandboxPidfd
	if err := sandbox.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = sandbox.Wait()
	p.SetExited(0)
	p.SetExited(0)
	if p.sandboxPidfd != -1 {
		t.Fatal("terminal exit retained its pidfd")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("pidfd after exit: %v, want closed descriptor", err)
	}
	requireLiveProcess(t, neighborPipe)
}

func TestInitExitRetainsLiveSandboxForExplicitDelete(t *testing.T) {
	for _, status := range []int{0, InternalErrorCode} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.Sandbox = true
			p.Platform = fakePlatform{}
			_, pipe := pinnedTestProcess(t, p)
			neighbor := New("neighbor", nil, stdio.Stdio{})
			_, neighborPipe := pinnedTestProcess(t, neighbor)
			p.SetExited(status)
			requireLiveProcess(t, pipe)
			if p.sandboxPidfd < 0 {
				t.Fatal("init exit discarded the still-live sandbox process handle")
			}
			if err := p.Delete(context.Background()); err == nil {
				t.Fatal("Delete succeeded against a wedged runtime")
			}
			if err := pipe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var buf [1]byte
			if _, err := pipe.Read(buf[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("explicit Delete left its wedged sandbox alive: %v", err)
			}
			if p.sandboxPidfd != -1 {
				t.Fatal("successful sandbox termination retained its pidfd")
			}
			requireLiveProcess(t, neighborPipe)
		})
	}
}

func TestOnlyExplicitSandboxTeardownEscalates(t *testing.T) {
	for _, tc := range []struct {
		name           string
		sandbox        bool
		locked         bool
		signal         uint32
		all            bool
		operation      string
		callerTimeout  bool
		callerCanceled bool
		withoutPidfd   bool
		fuseAbort      bool
		kill           bool
	}{
		{name: "ExplicitKill", sandbox: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", kill: true},
		{name: "ExplicitKillBehindLock", sandbox: true, locked: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill"},
		{name: "ExplicitKillWithFuseAbort", sandbox: true, fuseAbort: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", kill: true},
		{name: "SIGTERM", sandbox: true, signal: uint32(unix.SIGTERM), all: true, operation: "Kill"},
		{name: "WithoutAll", sandbox: true, signal: uint32(unix.SIGKILL), operation: "Kill"},
		{name: "Workload", signal: uint32(unix.SIGKILL), all: true, operation: "Kill"},
		{name: "CallerDeadline", sandbox: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", callerTimeout: true},
		{name: "CallerDeadlineBehindLock", sandbox: true, locked: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", callerTimeout: true},
		{name: "CanceledCaller", sandbox: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", callerCanceled: true},
		{name: "WithoutPidfd", sandbox: true, signal: uint32(unix.SIGKILL), all: true, operation: "Kill", withoutPidfd: true},
		{name: "AutomaticKillAll", sandbox: true, operation: "KillAll"},
		{name: "Delete", sandbox: true, operation: "Delete", kill: true},
		{name: "DeleteBehindLock", sandbox: true, locked: true, operation: "Delete"},
		{name: "DeleteWithFuseAbort", sandbox: true, fuseAbort: true, operation: "Delete", kill: true},
		{name: "WorkloadDelete", operation: "Delete"},
		{name: "CallerDeadlineDelete", sandbox: true, operation: "Delete", callerTimeout: true},
		{name: "CanceledCallerDelete", sandbox: true, operation: "Delete", callerCanceled: true},
		{name: "DeleteWithoutPidfd", sandbox: true, operation: "Delete", withoutPidfd: true},
		{name: "Stats", sandbox: true, operation: "Stats"},
		{name: "Status", sandbox: true, operation: "Status"},
		{name: "Checkpoint", sandbox: true, operation: "Checkpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.Sandbox = tc.sandbox
			p.FuseAbort = tc.fuseAbort
			_, pipe := pinnedTestProcess(t, p)
			neighbor := New("neighbor", nil, stdio.Stdio{})
			neighborProcess, neighborPipe := pinnedTestProcess(t, neighbor)
			if tc.withoutPidfd {
				p.closeSandboxPidfd()
				p.pid = neighborProcess.Process.Pid
			}
			if tc.locked {
				p.mu.Lock()
				defer p.mu.Unlock()
			}
			ctx := context.Background()
			if tc.callerTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			}
			if tc.callerCanceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			start := time.Now()
			var err error
			switch tc.operation {
			case "Kill":
				err = p.Kill(ctx, tc.signal, tc.all)
			case "KillAll":
				p.KillAll(ctx)
			case "Delete":
				p.initState = &stoppedState{process: p}
				err = p.Delete(ctx)
			case "Stats":
				_, err = p.Stats(ctx, p.id)
			case "Status":
				_, err = p.Status(ctx)
			case "Checkpoint":
				err = p.CheckpointSandbox(ctx, &runsccmd.CheckpointOpts{})
			}
			if tc.operation != "KillAll" && err == nil {
				t.Fatal("operation succeeded against a wedged runtime")
			}
			requireBounded(t, start)
			if tc.kill {
				if err := pipe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var buf [1]byte
				if _, err := pipe.Read(buf[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("sandbox survived explicit SIGKILL --all: %v", err)
				}
			} else {
				requireLiveProcess(t, pipe)
			}
			requireLiveProcess(t, neighborPipe)
		})
	}
}

func TestLongRuntimeOperationsAreBounded(t *testing.T) {
	for _, name := range []string{"Start", "Restore", "Checkpoint"} {
		t.Run(name, func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.Platform = fakePlatform{}
			p.Sandbox = true
			p.initState = &createdState{p: p}
			start := time.Now()
			var err error
			switch name {
			case "Start":
				err = p.Start(context.Background())
			case "Restore":
				err = p.Restore(context.Background(), &extension.RestoreConfig{ImagePath: t.TempDir()})
			case "Checkpoint":
				p.initState = &runningState{p: p}
				err = p.CheckpointSandbox(context.Background(), &runsccmd.CheckpointOpts{})
			}
			if err == nil {
				t.Fatal("operation succeeded against a wedged runtime")
			}
			requireBounded(t, start)
		})
	}
}

func TestDeleteBoundsBlockedUnmountAndReusesWorker(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Rootfs = t.TempDir()
	p.initState = &stoppedState{process: p}
	fake := filepath.Join(t.TempDir(), "successful-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = fake
	old := unmountRootfs
	release, finished := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var finishOnce sync.Once
	unmountRootfs = func(path string, flags int) error {
		calls.Add(1)
		defer finishOnce.Do(func() { close(finished) })
		if path != p.Rootfs || flags != 0 {
			return fmt.Errorf("unmount(%q, %d), want (%q, 0)", path, flags, p.Rootfs)
		}
		<-release
		return nil
	}
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() { unblock(); <-finished; unmountRootfs = old })
	for range 2 {
		start := time.Now()
		if err := p.Delete(context.Background()); !errors.Is(err, errRunscTimeout) {
			t.Fatalf("Delete error = %v, want bounded unmount failure", err)
		}
		requireBounded(t, start)
	}
	if calls.Load() != 1 {
		t.Fatalf("Delete retries started %d blocked workers, want one", calls.Load())
	}
	unblock()
	<-finished
	if err := p.Delete(context.Background()); err != nil {
		t.Fatalf("Delete retry after unmount recovery: %v", err)
	}
}

func TestTeardownDoesNotInterruptCheckpoint(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	runscTimeout = 100 * time.Millisecond
	runscLongOperationTimeout = 3 * time.Second
	p.Sandbox = true
	_, pipe := pinnedTestProcess(t, p)
	dir := t.TempDir()
	marker := filepath.Join(dir, "checkpoint-started")
	fake := filepath.Join(dir, "runsc")
	script := "#!/bin/sh\necho started > " + strconv.Quote(marker) + "\nexec sleep 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = fake
	done := make(chan error, 1)
	go func() { done <- p.CheckpointSandbox(context.Background(), &runsccmd.CheckpointOpts{}) }()
	t.Cleanup(func() {
		if err := <-done; err != nil {
			t.Errorf("checkpoint failed: %v", err)
		}
	})
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("checkpoint did not start")
		}
		time.Sleep(time.Millisecond)
	}
	for _, call := range []func() error{
		func() error { return p.Delete(context.Background()) },
		func() error { return p.Kill(context.Background(), uint32(unix.SIGKILL), true) },
	} {
		if err := call(); !errors.Is(err, errRunscTimeout) {
			t.Fatalf("contended teardown error = %v, want shim timeout", err)
		}
		requireLiveProcess(t, pipe)
	}
}

type outputTestIO struct {
	runc.IO
	output io.ReadCloser
}

func (p *outputTestIO) Stdout() io.ReadCloser { return p.output }
func (*outputTestIO) Stderr() io.ReadCloser   { return io.NopCloser(strings.NewReader("")) }
func (p *outputTestIO) Close() error          { return p.output.Close() }

func TestDeleteClosesBlockedOutputPipe(t *testing.T) {
	p := newRuntimeWedgedInit(t)
	p.Sandbox = true
	p.initState = &stoppedState{process: p}
	_, sandboxPipe := pinnedTestProcess(t, p)
	dir := t.TempDir()
	fake := filepath.Join(dir, "runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.runtime.Command = fake
	path := filepath.Join(dir, "stdout")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	p.io = &outputTestIO{output: io.NopCloser(strings.NewReader(strings.Repeat("x", 1<<20)))}
	t.Cleanup(func() {
		p.closeIO()
		_ = reader.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = io.Copy(io.Discard, reader)
		_ = reader.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := copyPipes(ctx, p.io, "", path, os.DevNull, &p.wg, &p.closers); err != nil {
		t.Fatal(err)
	}
	for {
		queued, err := unix.IoctlGetInt(int(reader.Fd()), unix.TIOCINQ)
		if err != nil {
			t.Fatal(err)
		}
		if queued > 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("output writer did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := p.Delete(context.Background()); !errors.Is(err, errRunscTimeout) {
		t.Fatalf("blocked pipe Delete = %v, want timeout", err)
	}
	requireLiveProcess(t, sandboxPipe)
	select {
	case <-p.ioDone:
	case <-ctx.Done():
		t.Fatal("timed-out deletion left the output copy blocked")
	}
	old := unmountRootfs
	unmountRootfs = func(string, int) error { return nil }
	t.Cleanup(func() { unmountRootfs = old })
	if err := p.Delete(context.Background()); err != nil {
		t.Fatalf("Delete retry after closing output: %v", err)
	}
}

func TestFailedDeleteRetainsOnlyLivePidfd(t *testing.T) {
	for _, exited := range []bool{false, true} {
		t.Run(strconv.FormatBool(exited), func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.Sandbox = true
			p.initState = &stoppedState{process: p}
			sandbox, pipe := pinnedTestProcess(t, p)
			fd := p.sandboxPidfd
			if exited {
				_ = sandbox.Process.Kill()
				_ = sandbox.Wait()
			}
			fake := filepath.Join(t.TempDir(), "runsc")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			p.runtime.Command = fake
			oldUnmount := unmountRootfs
			unmountRootfs = func(string, int) error { return nil }
			t.Cleanup(func() { unmountRootfs = oldUnmount })
			if err := p.Delete(context.Background()); err == nil {
				t.Fatal("failed runtime delete reported success")
			}
			if exited {
				if p.sandboxPidfd != -1 {
					t.Fatal("failed delete retained an exited sandbox descriptor")
				}
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Fatalf("exited pidfd is not closed: %v", err)
				}
			} else {
				if p.sandboxPidfd != fd {
					t.Fatal("failed delete discarded the live sandbox identity")
				}
				requireLiveProcess(t, pipe)
				if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := p.Delete(context.Background()); !errors.Is(err, errRunscTimeout) {
					t.Fatalf("wedged retry error = %v", err)
				}
				if err := pipe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				var buf [1]byte
				if _, err := pipe.Read(buf[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("retry failed to kill its pinned sandbox: %v", err)
				}
			}
		})
	}
}

func TestDeleteTimeoutAfterSuccessfulKill(t *testing.T) {
	for _, sandboxTask := range []bool{true, false} {
		t.Run(fmt.Sprintf("Sandbox=%t", sandboxTask), func(t *testing.T) {
			p := newRuntimeWedgedInit(t)
			p.initState = &stoppedState{process: p}
			p.Sandbox = sandboxTask
			sandbox := exec.Command("sleep", "60")
			if err := sandbox.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sandbox.Process.Kill(); _ = sandbox.Wait() })
			p.sandboxPidfd = testPidfd(t, sandbox.Process.Pid)
			t.Cleanup(p.closeSandboxPidfd)
			neighbor := exec.Command("sleep", "60")
			if err := neighbor.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = neighbor.Process.Kill(); _ = neighbor.Wait() })
			dir := t.TempDir()
			fake := filepath.Join(dir, "delete-wedged-runsc")
			marker := filepath.Join(dir, "delete-reached")
			script := "#!/bin/sh\nfor arg do\nif [ \"$arg\" = delete ]; then\necho reached > " + strconv.Quote(marker) + "\nexec >/dev/null 2>&1\nexec sleep 60\nfi\ndone\nexit 0\n"
			if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			p.runtime.Command = fake
			start := time.Now()
			if err := p.Delete(context.Background()); err == nil {
				t.Fatal("Delete succeeded against wedged delete command")
			}
			requireBounded(t, start)
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("successful kill never reached Delete: %v", err)
			}
			if sandboxTask {
				done := make(chan error, 1)
				go func() { done <- sandbox.Wait() }()
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("Delete timeout did not terminate its sandbox")
				}
			} else if err := sandbox.Process.Signal(unix.Signal(0)); err != nil {
				t.Fatalf("workload Delete killed sandbox: %v", err)
			}
			if err := neighbor.Process.Signal(unix.Signal(0)); err != nil {
				t.Fatalf("neighbor was affected: %v", err)
			}
		})
	}
}
