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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/v2/core/events"
	types "github.com/containerd/containerd/v2/pkg/protobuf/types"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
)

type mockPublisher struct{}

var _ shim.Publisher = (*mockPublisher)(nil)

func (m *mockPublisher) Publish(ctx context.Context, topic string, event events.Event) error {
	return nil
}

func (m *mockPublisher) Close() error {
	return nil
}

// TestShutdownSocketCleanup verifies that the shim cleans up its Unix socket
// when receiving a Shutdown request.
func TestShutdownSocketCleanup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shim-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "shim.sock")

	// Create a dummy file to simulate the socket.
	if err := os.WriteFile(socketPath, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create dummy socket file: %v", err)
	}

	// Write the "address" file which NewShimRedirector reads.
	addressContent := "unix://" + socketPath
	if err := os.WriteFile(filepath.Join(tmpDir, "address"), []byte(addressContent), 0644); err != nil {
		t.Fatalf("Failed to write address file: %v", err)
	}

	// Temporarily change CWD to tmpDir so NewShimRedirector can find "address" file.
	origCwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origCwd)

	ctx, sd := shutdown.WithShutdown(context.Background())

	p := &mockPublisher{}
	srv, err := NewShimRedirector(ctx, p, sd)
	if err != nil {
		t.Fatalf("NewShimRedirector failed: %v", err)
	}

	redirector := srv.(*shimRedirector)

	// Trigger Shutdown.
	_, err = redirector.Shutdown(ctx, &task.ShutdownRequest{ID: "test-id"})
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Wait for the shutdown callbacks to complete.
	select {
	case <-sd.Done():
		// Graceful exit after callbacks completed.
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for shutdown callbacks")
	}

	// Verify that the socket file was removed.
	if _, err := os.Stat(socketPath); err == nil {
		t.Errorf("Socket file %s still exists, cleanup failed", socketPath)
	} else if !os.IsNotExist(err) {
		t.Errorf("Unexpected error checking socket file: %v", err)
	}
}

// fakeTaskService is an extension.TaskServiceExt that only implements
// Shutdown. Calling any other method panics.
type fakeTaskService struct {
	extension.TaskServiceExt

	shutdownResp *types.Empty
	shutdownErr  error
}

func (f *fakeTaskService) Shutdown(context.Context, *task.ShutdownRequest) (*types.Empty, error) {
	return f.shutdownResp, f.shutdownErr
}

// fakeShutdownService records whether shutdown was initiated. Calling any
// method other than Shutdown panics.
type fakeShutdownService struct {
	shutdown.Service

	shutdownCalled bool
}

func (f *fakeShutdownService) Shutdown() {
	f.shutdownCalled = true
}

// TestShutdownResponse verifies that Shutdown always acknowledges the request
// with a non-nil response, and only shuts down the shim once it no longer
// services any container.
func TestShutdownResponse(t *testing.T) {
	for _, tc := range []struct {
		name         string
		main         *fakeTaskService
		wantShutdown bool
	}{
		{
			name:         "no containers",
			main:         &fakeTaskService{shutdownResp: &types.Empty{}},
			wantShutdown: true,
		},
		{
			// With shim grouping, a single shim services all containers of a
			// pod and receives a Shutdown request every time one of them is
			// deleted.
			name:         "still servicing containers",
			main:         &fakeTaskService{shutdownErr: errors.New("shim still servicing 1 containers")},
			wantShutdown: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := &fakeShutdownService{}
			s := &shimRedirector{
				main:     tc.main,
				shutdown: sd,
			}
			resp, err := s.Shutdown(context.Background(), &task.ShutdownRequest{ID: "test-id"})
			if err != nil {
				t.Fatalf("Shutdown() failed: %v", err)
			}
			// ttrpc fails to marshal a nil response, which turns the request
			// into an error for the caller (containerd).
			if resp == nil {
				t.Errorf("Shutdown() returned a nil response")
			}
			if sd.shutdownCalled != tc.wantShutdown {
				t.Errorf("Shutdown() initiated shim shutdown: %t, want: %t", sd.shutdownCalled, tc.wantShutdown)
			}
		})
	}
}
