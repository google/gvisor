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

package client

import (
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
)

func TestClientNew(t *testing.T) {
	// Test New with nil config
	cNil := New(nil)
	if got, want := cNil.RootDir(), config.DefaultRootDir(); got != want {
		t.Errorf("New(nil).RootDir() = %q, want %q", got, want)
	}

	// Test New with empty RootDir
	cEmpty := New(&config.Config{})
	if got, want := cEmpty.RootDir(), config.DefaultRootDir(); got != want {
		t.Errorf("New(&Config{}).RootDir() = %q, want %q", got, want)
	}

	// Test New with config
	conf := &config.Config{
		RootDir: "/tmp/runsc-test",
		Debug:   true,
	}
	c := New(conf)
	if got := c.RootDir(); got != "/tmp/runsc-test" {
		t.Errorf("RootDir() = %q, want %q", got, "/tmp/runsc-test")
	}
	if got := c.Config(); got != conf {
		t.Errorf("Config() = %v, want %v", got, conf)
	}
	if !c.Config().Debug {
		t.Errorf("Config().Debug = false, want true")
	}

	// Test NewFromRootDir
	cRoot := NewFromRootDir("/tmp/custom-root")
	if got := cRoot.RootDir(); got != "/tmp/custom-root" {
		t.Errorf("NewFromRootDir().RootDir() = %q, want %q", got, "/tmp/custom-root")
	}
}

func TestClientLoadNonExistent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "runsc-client-test-")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	c := NewFromRootDir(tmpDir)
	_, err = c.Load(context.Background(), "nonexistent-container-id", container.LoadOpts{})
	if err == nil {
		t.Fatalf("Load() expected error for nonexistent container, got nil")
	}
}

func TestClientPauseResumeStateNonExistent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "runsc-client-test-")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	c := NewFromRootDir(tmpDir)
	ctx := context.Background()

	if err := c.Pause(ctx, "nonexistent"); err == nil {
		t.Errorf("Pause() expected error for nonexistent container, got nil")
	}
	if err := c.Resume(ctx, "nonexistent"); err == nil {
		t.Errorf("Resume() expected error for nonexistent container, got nil")
	}
	if _, err := c.State(ctx, "nonexistent"); err == nil {
		t.Errorf("State() expected error for nonexistent container, got nil")
	}
	if _, err := c.Spec(ctx, "nonexistent"); err == nil {
		t.Errorf("Spec() expected error for nonexistent container, got nil")
	}
}

func TestClientListEmpty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "runsc-client-test-")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	c := NewFromRootDir(tmpDir)
	list, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("List() returned %d items, want 0", len(list))
	}
}

func TestClientContextCancellation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "runsc-client-test-")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	c := NewFromRootDir(tmpDir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = c.Load(ctx, "any-id", container.LoadOpts{})
	if err != context.Canceled {
		t.Errorf("Load() with canceled context: got %v, want %v", err, context.Canceled)
	}

	_, err = c.List(ctx)
	if err != context.Canceled {
		t.Errorf("List() with canceled context: got %v, want %v", err, context.Canceled)
	}
}
