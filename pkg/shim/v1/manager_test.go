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

package v1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/namespaces"
	"golang.org/x/sys/unix"

	typeurl "github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go/features"

	"gvisor.dev/gvisor/pkg/shim/v1/runsc"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestResolveGrouping verifies that resolveGrouping correctly extracts the
// sandbox ID from both containerd and CRI-O annotations.
func TestResolveGrouping(t *testing.T) {
	const containerID = "test-container-id"
	const sandboxID = "test-sandbox-id"

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{
			name:        "containerd annotation",
			annotations: map[string]string{kubernetesGroupAnnotation: sandboxID},
			want:        sandboxID,
		},
		{
			name:        "crio annotation",
			annotations: map[string]string{specutils.CRIOSandboxIDAnnotation: sandboxID},
			want:        sandboxID,
		},
		{
			name: "containerd takes precedence over crio",
			annotations: map[string]string{
				kubernetesGroupAnnotation:         "containerd-sandbox",
				specutils.CRIOSandboxIDAnnotation: "crio-sandbox",
			},
			want: "containerd-sandbox",
		},
		{
			name:        "no annotation returns container ID",
			annotations: map[string]string{},
			want:        containerID,
		},
		{
			name:        "nil annotations returns container ID",
			annotations: nil,
			want:        containerID,
		},
		{
			name:        "unrelated annotations returns container ID",
			annotations: map[string]string{"io.kubernetes.cri-o.ContainerType": "container"},
			want:        containerID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveGrouping(containerID, tc.annotations)
			if got != tc.want {
				t.Errorf("resolveGrouping(%q, %v) = %q, want %q", containerID, tc.annotations, got, tc.want)
			}
		})
	}
}

// TestManagerInfo verifies that the Info() call returns the expected information
// about the runtime.
func TestManagerInfo(t *testing.T) {
	m := NewShimManager("io.containerd.runsc.v1")
	info, err := m.Info(context.Background(), bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("Standalone ShimManager::Info call returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatalf("ShimManager::Info got nil, want non-nil RuntimeInfo")
	}
	if info.Features == nil {
		t.Fatalf("ShimManager::Info got nil, want populated Features struct from specutils")
	}

	decoded, err := typeurl.UnmarshalAny(info.Features)
	if err != nil {
		t.Fatalf("Failed to deserialize info.Features Any proto: %v", err)
	}

	_, ok := decoded.(*features.Features)
	if !ok {
		t.Fatalf("Decoded features is type %T, want *features.Features", decoded)
	}

}

func TestManagerStopBoundsWedgedRuntime(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked-cleanup=%t", blocked), func(t *testing.T) {
			oldTimeout, oldUnmount := stopRunscTimeout, unmountRootfs
			stopRunscTimeout = 100 * time.Millisecond
			dir := t.TempDir()
			t.Chdir(dir)
			fake := filepath.Join(dir, "fake-runsc")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			st := runsc.State{Options: runsc.Options{BinaryName: fake, Root: dir}, Rootfs: dir}
			if err := st.Save(dir); err != nil {
				t.Fatal(err)
			}
			release, finished := make(chan struct{}), make(chan struct{})
			mountErr := errors.New("injected-unmount-failure")
			var calls atomic.Int32
			unmountRootfs = func(path string, flags int) error {
				calls.Add(1)
				defer close(finished)
				if path != dir || flags != 0 {
					return fmt.Errorf("unmount(%q, %d), want (%q, 0)", path, flags, dir)
				}
				if blocked {
					<-release
				}
				return mountErr
			}
			t.Cleanup(func() {
				close(release)
				if calls.Load() != 0 {
					<-finished
				}
				stopRunscTimeout, unmountRootfs = oldTimeout, oldUnmount
			})
			start := time.Now()
			status, err := (&manager{}).Stop(namespaces.WithNamespace(context.Background(), "test"), "test")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Stop error = %v, want deadline failure", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("timed-out Delete skipped cleanup: %d calls", calls.Load())
			}
			if !blocked && !errors.Is(err, mountErr) {
				t.Fatalf("Stop lost cleanup error after Delete timeout: %v", err)
			}
			if !status.ExitedAt.IsZero() || status.ExitStatus != 0 {
				t.Fatalf("failed Stop reported success: %+v", status)
			}
			minimum := stopRunscTimeout
			if blocked {
				minimum *= 2
			}
			if elapsed := time.Since(start); elapsed < minimum || elapsed > 2*time.Second {
				t.Fatalf("Stop returned after %v, want bounded runtime and cleanup waits", elapsed)
			}
		})
	}
}

func TestManagerStopPreservesCallerCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			oldTimeout, oldUnmount := stopRunscTimeout, unmountRootfs
			stopRunscTimeout = time.Second
			dir := t.TempDir()
			t.Chdir(dir)
			fake := filepath.Join(dir, "fake-runsc")
			if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec >/dev/null 2>&1\nexec sleep 60\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			st := runsc.State{Options: runsc.Options{BinaryName: fake, Root: dir}, Rootfs: dir}
			if err := st.Save(dir); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			unmountRootfs = func(string, int) error { calls.Add(1); return nil }
			t.Cleanup(func() { stopRunscTimeout, unmountRootfs = oldTimeout, oldUnmount })
			ctx := namespaces.WithNamespace(context.Background(), "test")
			want := errors.New("caller canceled teardown")
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				want = context.DeadlineExceeded
			} else {
				var cancelCause context.CancelCauseFunc
				ctx, cancelCause = context.WithCancelCause(ctx)
				timer := time.AfterFunc(50*time.Millisecond, func() { cancelCause(want) })
				cancel = func() { timer.Stop(); cancelCause(want) }
			}
			defer cancel()
			start := time.Now()
			status, err := (&manager{}).Stop(ctx, "test")
			if !errors.Is(err, want) || calls.Load() != 0 || !status.ExitedAt.IsZero() {
				t.Fatalf("caller cancellation = %+v, %v, cleanup calls %d", status, err, calls.Load())
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("Stop ignored caller cancellation")
			}
		})
	}
}

func TestManagerStopBoundsBlockedUnmountAndReportsFailure(t *testing.T) {
	oldTimeout, oldUnmount := stopRunscTimeout, unmountRootfs
	stopRunscTimeout = 200 * time.Millisecond
	dir := t.TempDir()
	t.Chdir(dir)
	fake := filepath.Join(dir, "successful-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := runsc.State{Options: runsc.Options{BinaryName: fake, Root: dir}, Rootfs: dir}
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	release, finished := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var finishOnce sync.Once
	unmountRootfs = func(path string, flags int) error {
		calls.Add(1)
		defer finishOnce.Do(func() { close(finished) })
		if path != dir || flags != 0 {
			return fmt.Errorf("unmount(%q, %d), want (%q, 0)", path, flags, dir)
		}
		<-release
		return nil
	}
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() { unblock(); <-finished; stopRunscTimeout, unmountRootfs = oldTimeout, oldUnmount })
	ctx := namespaces.WithNamespace(context.Background(), "test")
	for range 2 {
		start := time.Now()
		status, err := (&manager{}).Stop(ctx, "test")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Stop error = %v, want unmount timeout", err)
		}
		if !status.ExitedAt.IsZero() || status.ExitStatus != 0 {
			t.Fatalf("failed Stop reported success: %+v", status)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("Stop waited indefinitely for unmount")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("Stop retries started %d blocked workers, want one", calls.Load())
	}
	unblock()
	<-finished
	if _, err := (&manager{}).Stop(ctx, "test"); err != nil {
		t.Fatalf("Stop retry after unmount recovery: %v", err)
	}
}

func TestManagerStopCleansRootfsAfterDeleteFailure(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	fake := filepath.Join(dir, "failing-runsc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho injected-delete-failure >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := runsc.State{Options: runsc.Options{BinaryName: fake, Root: dir}, Rootfs: dir}
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	old := unmountRootfs
	t.Cleanup(func() { unmountRootfs = old })
	var calls atomic.Int32
	mountErr := errors.New("injected-unmount-failure")
	unmountRootfs = func(path string, flags int) error {
		if path != dir || flags != 0 {
			return fmt.Errorf("unmount(%q, %d), want (%q, 0)", path, flags, dir)
		}
		if calls.Add(1) == 1 {
			return mountErr
		}
		return nil
	}
	ctx := namespaces.WithNamespace(context.Background(), "test")
	for attempt := int32(1); attempt <= 2; attempt++ {
		status, err := (&manager{}).Stop(ctx, "test")
		if err == nil || !strings.Contains(err.Error(), "delete runsc container") {
			t.Fatalf("Stop error = %v, want original deletion failure", err)
		}
		if attempt == 1 && !errors.Is(err, mountErr) {
			t.Fatalf("Stop lost unmount error: %v", err)
		}
		if !status.ExitedAt.IsZero() || status.ExitStatus != 0 {
			t.Fatalf("failed Stop reported success: %+v", status)
		}
		if calls.Load() != attempt {
			t.Fatalf("failed Delete skipped rootfs cleanup on attempt %d", attempt)
		}
	}
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	status, err := (&manager{}).Stop(ctx, "test")
	if err != nil || status.ExitedAt.IsZero() || status.ExitStatus != 128+int(unix.SIGKILL) {
		t.Fatalf("Stop after runtime recovery = %+v, %v", status, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("successful retry skipped cleanup: %d", calls.Load())
	}
}
