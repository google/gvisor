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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/stdio"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func newExitTestInit(t *testing.T) (*Init, *exec.Cmd) {
	t.Helper()
	t.Setenv("GVISOR_SHIM_TEST_RUNTIME_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	bundle := t.TempDir()
	command, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child, _ := sandboxIdentityProcess(t, bundle, command)
	if err := os.WriteFile(filepath.Join(bundle, "init.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New("root", &runsccmd.Runsc{Command: command, Root: bundle}, stdio.Stdio{})
	p.Bundle = bundle
	p.Sandbox = true
	p.Platform = fakePlatform{}
	t.Cleanup(func() {
		if p.cancelSandboxExit != nil {
			p.cancelSandboxExit()
		}
		p.closeIO()
		p.closeSandboxPidfd()
	})
	return p, child
}

func killExitTestChild(t *testing.T, child *exec.Cmd) {
	t.Helper()
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
}

func TestSandboxExitBeforeStart(t *testing.T) {
	for _, phase := range []string{"create", "start", "restore", "deleted"} {
		t.Run(phase, func(t *testing.T) {
			p, child := newExitTestInit(t)
			if phase == "create" {
				if err := os.WriteFile(filepath.Join(p.Bundle, "kill-during-create"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
				t.Fatal(err)
			}
			if phase == "start" || phase == "restore" {
				if err := os.WriteFile(filepath.Join(p.Bundle, "fail-start"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				var err error
				if phase == "restore" {
					err = p.Restore(t.Context(), &extension.RestoreConfig{})
				} else {
					err = p.Start(t.Context())
				}
				if err == nil {
					t.Fatal("start/restore unexpectedly succeeded")
				}
			}
			if phase == "deleted" {
				if err := p.Delete(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "create" {
				killExitTestChild(t, child)
			}
			status, ok := p.WaitSandboxExit()
			if !ok || status != InternalErrorCode {
				t.Fatalf("pre-start exit = (%d, %t), want (%d, true)", status, ok, InternalErrorCode)
			}
			if !p.SetExitedBeforeStart(func() int { return status }) {
				t.Fatal("pre-start exit rejected")
			}
			if !p.isExited() || p.ExitStatus() != InternalErrorCode || p.ExitedAt().IsZero() {
				t.Fatal("exit did not complete Wait and metadata")
			}
			if phase == "deleted" {
				if _, ok := p.initState.(*deletedState); !ok {
					t.Fatal("exit revived a deleted task")
				}
			}
			if p.SetExitedBeforeStart(func() int { t.Fatal("duplicate exit consumed status"); return 0 }) {
				t.Fatal("duplicate exit accepted")
			}
		})
	}
}

func TestSandboxFailedStartRemainsLiveUntilExit(t *testing.T) {
	p, _ := newExitTestInit(t)
	if err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Bundle, "fail-start"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(t.Context()); err == nil {
		t.Fatal("Start succeeded")
	}
	if p.isExited() {
		t.Fatal("failed Start exited a living sandbox")
	}
	select {
	case <-p.sandboxExit:
		t.Fatal("living sandbox reported an exit")
	default:
	}
	if err := os.Remove(filepath.Join(p.Bundle, "fail-start")); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, exited := p.WaitSandboxExit(); exited {
		t.Fatal("successful retry did not hand off to runsc wait")
	}
	select {
	case e := <-ExitCh:
		if e.ID != p.id || e.Status != 17 {
			t.Fatalf("normal wait event = %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normal wait did not report the guest exit")
	}
}

func TestSandboxBufferedExitDoesNotReplaceStartedExit(t *testing.T) {
	for _, restore := range []bool{false, true} {
		p, child := newExitTestInit(t)
		if err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
			t.Fatal(err)
		}
		killExitTestChild(t, child)
		var err error
		if restore {
			err = p.Restore(t.Context(), &extension.RestoreConfig{})
		} else {
			err = p.Start(t.Context())
		}
		if err != nil {
			t.Fatal(err)
		}
		p.WaitSandboxExit()
		if p.SetExitedBeforeStart(func() int { t.Fatal("host exit stole normal exit processing"); return 137 }) {
			t.Fatal("host exit replaced normal waiter")
		}
		select {
		case e := <-ExitCh:
			if e.Status != 17 {
				t.Fatalf("guest status = %d, want 17", e.Status)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("normal wait did not complete")
		}
	}
}

func TestSandboxExitUsesDescriptorInsteadOfNumericPID(t *testing.T) {
	p, child := newExitTestInit(t)
	if err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
		t.Fatal(err)
	}
	// The original host PID can refer to another process after reaping.
	p.pid = os.Getpid()
	killExitTestChild(t, child)
	if status, ok := p.WaitSandboxExit(); !ok || status != InternalErrorCode {
		t.Fatalf("original process death was lost: (%d, %t)", status, ok)
	}
}

func TestSandboxCreateFailureClosesObserver(t *testing.T) {
	for _, afterRuntime := range []bool{false, true} {
		p, _ := newExitTestInit(t)
		cfg := &CreateConfig{ID: p.id, Bundle: p.Bundle}
		if afterRuntime {
			cfg.Stdin = filepath.Join(p.Bundle, "absent", "stdin")
		} else {
			p.runtime.Command = "/nonexistent-runsc"
		}
		if err := p.Create(t.Context(), cfg); err == nil {
			t.Fatal("Create succeeded")
		}
		if afterRuntime {
			if _, exited := p.WaitSandboxExit(); exited {
				t.Fatal("failed Create declared its living sandbox dead")
			}
		}
	}
}

func TestSandboxObserverSetupFailureRollsBackCreate(t *testing.T) {
	p, child := newExitTestInit(t)
	for _, name := range []string{"invalid-pidfd", "delete-kills-test-child"} {
		if err := os.WriteFile(filepath.Join(p.Bundle, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd := testPidfd(t, child.Process.Pid)
	defer unix.Close(fd)
	err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle})
	if err == nil || !strings.Contains(err.Error(), "registering sandbox pidfd") {
		t.Fatalf("unpollable descriptor did not fail Create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.Bundle, "deleted")); err != nil {
		t.Fatalf("failed Create did not delete its runtime task: %v", err)
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 1000); err != nil || n != 1 {
		t.Fatalf("rollback left its sandbox alive: poll=(%d, %v)", n, err)
	}
	if p.sandboxPidfd != -1 || p.cancelSandboxExit != nil {
		t.Fatal("failed observer setup retained process handles")
	}
}

func TestSandboxCreateRollbackFailureTerminatesOwnedProcess(t *testing.T) {
	for _, failure := range []string{"observer", "io"} {
		t.Run(failure, func(t *testing.T) {
			p, child := newExitTestInit(t)
			if err := os.WriteFile(filepath.Join(p.Bundle, "fail-delete"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := &CreateConfig{ID: p.id, Bundle: p.Bundle}
			want := "failed to open stdin fifo"
			if failure == "observer" {
				if err := os.WriteFile(filepath.Join(p.Bundle, "invalid-pidfd"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				want = "registering sandbox pidfd"
			} else {
				cfg.Stdin = filepath.Join(p.Bundle, "absent", "stdin")
			}
			neighbor, _ := sandboxIdentityProcess(t, t.TempDir(), p.runtime.Command)
			fd := testPidfd(t, child.Process.Pid)
			defer unix.Close(fd)
			neighborFD := testPidfd(t, neighbor.Process.Pid)
			defer unix.Close(neighborFD)
			if err := p.Create(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Create error = %v, want original %q error", err, want)
			}
			if _, err := os.Stat(filepath.Join(p.Bundle, "deleted")); err != nil {
				t.Fatalf("rollback did not attempt runtime delete: %v", err)
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 1000); err != nil || n != 1 {
				t.Errorf("failed rollback left its sandbox alive: poll=(%d, %v)", n, err)
			}
			poll[0].Fd = int32(neighborFD)
			if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
				t.Errorf("rollback affected an unrelated process: poll=(%d, %v)", n, err)
			}
			if p.sandboxPidfd != -1 {
				t.Error("failed Create retained its signal descriptor")
			}
		})
	}
}

func TestSandboxTerminationAfterExitClosesDescriptor(t *testing.T) {
	p, child := newExitTestInit(t)
	if err := p.Create(t.Context(), &CreateConfig{ID: p.id, Bundle: p.Bundle}); err != nil {
		t.Fatal(err)
	}
	killExitTestChild(t, child)
	p.killSandbox("Create rollback failed")
	if p.sandboxPidfd != -1 {
		t.Fatal("already-exited sandbox retained its signal descriptor")
	}
}

func TestMissingSandboxPidfdRollsBackExpiredCreate(t *testing.T) {
	for _, cleanup := range []string{"healthy", "wedged"} {
		t.Run(cleanup, func(t *testing.T) {
			p, child := newExitTestInit(t)
			old := runscTimeout
			runscTimeout = 200 * time.Millisecond
			t.Cleanup(func() { runscTimeout = old })
			if cleanup == "wedged" {
				if err := os.WriteFile(filepath.Join(p.Bundle, "hang-delete"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"missing-pidfd", "delete-kills-test-child"} {
				if err := os.WriteFile(filepath.Join(p.Bundle, name), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fd := testPidfd(t, child.Process.Pid)
			defer unix.Close(fd)
			ctx, cancel := context.WithTimeoutCause(t.Context(), time.Second, errRunscTimeout)
			defer cancel()
			start := time.Now()
			err := p.Create(ctx, &CreateConfig{ID: p.id, Bundle: p.Bundle})
			requireBounded(t, start)
			if !errors.Is(err, errRunscTimeout) {
				t.Errorf("Create error = %v, want runtime timeout", err)
			}
			if _, err := os.Stat(filepath.Join(p.Bundle, "created-without-pidfd")); err != nil {
				t.Fatalf("runtime Create did not reach the missing-descriptor path: %v", err)
			}
			if _, err := os.Stat(filepath.Join(p.Bundle, "deleted")); err != nil {
				t.Errorf("expired Create skipped runtime cleanup: %v", err)
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if n, err := unix.Poll(poll, 1000); err != nil || n != 1 {
				t.Errorf("cleanup left its sandbox alive: poll=(%d, %v)", n, err)
			}
			if p.sandboxPidfd != -1 || p.cancelSandboxExit != nil {
				t.Error("failed Create retained process handles")
			}
		})
	}
}

func TestSandboxPidfdMessage(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			dir, err := os.MkdirTemp("", "pidfd-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			addr := &net.UnixAddr{Name: filepath.Join(dir, "socket"), Net: "unix"}
			listener, err := net.ListenUnix("unix", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialUnix("unix", nil, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fd := testPidfd(t, os.Getpid())
			defer unix.Close(fd)
			var fds []int
			for range count {
				fds = append(fds, fd)
			}
			if _, _, err := conn.WriteMsgUnix([]byte("pidfd"), unix.UnixRights(fds...), nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			received, err := receiveSandboxPidfd(ctx, listener)
			if count != 1 {
				if err == nil {
					unix.Close(received)
					t.Fatalf("accepted %d descriptors", count)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(received)
			flags, err := unix.FcntlInt(uintptr(received), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("received pidfd lacks close-on-exec: flags=%d err=%v", flags, err)
			}
			if err := unix.PidfdSendSignal(received, 0, nil, 0); err != nil {
				t.Fatalf("received descriptor does not reference the process: %v", err)
			}
		})
	}
}

func TestSandboxPidfdReceiveCancellation(t *testing.T) {
	for _, cause := range []error{context.Canceled, errRunscTimeout} {
		for _, connected := range []bool{false, true} {
			dir, err := os.MkdirTemp("", "pidfd-test")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			addr := &net.UnixAddr{Name: filepath.Join(dir, "socket"), Net: "unix"}
			listener, err := net.ListenUnix("unix", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if connected {
				conn, err := net.DialUnix("unix", nil, addr)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
			}
			ctx, cancel := context.WithCancelCause(t.Context())
			done := make(chan error, 1)
			go func() {
				_, err := receiveSandboxPidfd(ctx, listener)
				done <- err
			}()
			cancel(cause)
			select {
			case err := <-done:
				if !errors.Is(err, cause) {
					t.Fatalf("canceled receive = %v, want %v", err, cause)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not stop receive")
			}
		}
	}
}

func TestSandboxPidfdReceivePreservesSocketError(t *testing.T) {
	dir, err := os.MkdirTemp("", "pidfd-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "socket"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if _, err := receiveSandboxPidfd(t.Context(), listener); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("independently closed socket = %v, want net.ErrClosed", err)
	}
}
