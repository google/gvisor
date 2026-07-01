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

package utils

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func newTestUserNSConfig(t *testing.T) *UserNamespaceConfig {
	t.Helper()
	return &UserNamespaceConfig{
		HostUIDBase: 100000,
		HostGIDBase: 100000,
		RangeSize:   65536,
		PoolSize:    8,
		StateDir:    filepath.Join(t.TempDir(), "userns-pool"),
	}
}

func TestUserNamespaceConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*UserNamespaceConfig)
		wantErr bool
	}{
		{
			name:   "defaults populated",
			mutate: func(c *UserNamespaceConfig) {},
		},
		{
			name:    "missing host uid base",
			mutate:  func(c *UserNamespaceConfig) { c.HostUIDBase = 0 },
			wantErr: true,
		},
		{
			name:    "missing host gid base",
			mutate:  func(c *UserNamespaceConfig) { c.HostGIDBase = 0 },
			wantErr: true,
		},
		{
			name: "uint32 overflow",
			mutate: func(c *UserNamespaceConfig) {
				c.HostUIDBase = ^uint32(0) - 1
				c.RangeSize = 65536
				c.PoolSize = 1000
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestUserNSConfig(t)
			tc.mutate(c)
			err := c.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestAllocateUserNamespaceSlotUnique(t *testing.T) {
	c := newTestUserNSConfig(t)
	const want = 5
	got := make(map[uint32]string)
	for i := 0; i < want; i++ {
		id := "sandbox-" + string(rune('a'+i))
		slot, err := AllocateUserNamespaceSlot(c, id)
		if err != nil {
			t.Fatalf("AllocateUserNamespaceSlot(%q): %v", id, err)
		}
		if existing, ok := got[slot]; ok {
			t.Fatalf("slot %d allocated to %q and %q", slot, existing, id)
		}
		got[slot] = id
	}
	if len(got) != want {
		t.Fatalf("got %d unique slots, want %d", len(got), want)
	}
}

func TestAllocateUserNamespaceSlotIdempotent(t *testing.T) {
	c := newTestUserNSConfig(t)
	const id = "sandbox-A"
	first, err := AllocateUserNamespaceSlot(c, id)
	if err != nil {
		t.Fatalf("first AllocateUserNamespaceSlot: %v", err)
	}
	second, err := AllocateUserNamespaceSlot(c, id)
	if err != nil {
		t.Fatalf("second AllocateUserNamespaceSlot: %v", err)
	}
	if first != second {
		t.Errorf("idempotency: first=%d second=%d, want equal", first, second)
	}
}

func TestAllocateUserNamespaceSlotPoolExhausted(t *testing.T) {
	c := newTestUserNSConfig(t)
	for i := uint32(0); i < c.PoolSize; i++ {
		if _, err := AllocateUserNamespaceSlot(c, "filler-"+string(rune('a'+i))); err != nil {
			t.Fatalf("filler %d: %v", i, err)
		}
	}
	_, err := AllocateUserNamespaceSlot(c, "overflow")
	if !errors.Is(err, errPoolExhausted) {
		t.Errorf("got %v, want errPoolExhausted", err)
	}
}

func TestReleaseUserNamespaceSlotFreesSlot(t *testing.T) {
	c := newTestUserNSConfig(t)
	const id = "sandbox-A"
	first, err := AllocateUserNamespaceSlot(c, id)
	if err != nil {
		t.Fatalf("AllocateUserNamespaceSlot: %v", err)
	}
	if err := ReleaseUserNamespaceSlot(c, id); err != nil {
		t.Fatalf("ReleaseUserNamespaceSlot: %v", err)
	}
	// After release, a different sandbox should be able to claim the slot
	// (or any other free slot) without error.
	again, err := AllocateUserNamespaceSlot(c, "sandbox-B")
	if err != nil {
		t.Fatalf("re-allocate: %v", err)
	}
	if again != first {
		t.Logf("re-allocated slot %d (originally %d); both are valid outcomes", again, first)
	}
	// Releasing an unknown sandbox is a no-op (no error).
	if err := ReleaseUserNamespaceSlot(c, "never-allocated"); err != nil {
		t.Errorf("release unknown: got %v, want nil", err)
	}
}

func TestAllocateUserNamespaceSlotConcurrent(t *testing.T) {
	c := newTestUserNSConfig(t)
	c.PoolSize = 64
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)
	slots := make([]uint32, goroutines)
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			slots[i], errs[i] = AllocateUserNamespaceSlot(c, "concurrent-"+string(rune('a'+i)))
		}()
	}
	wg.Wait()

	seen := make(map[uint32]int, goroutines)
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
			continue
		}
		if prev, ok := seen[slots[i]]; ok {
			t.Errorf("slot %d collided: goroutines %d and %d", slots[i], prev, i)
		}
		seen[slots[i]] = i
	}
}

func TestInjectUserNamespaceMutatesSpec(t *testing.T) {
	c := newTestUserNSConfig(t)
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	spec := &specs.Spec{}
	const slot = 3

	updated, err := InjectUserNamespace(spec, c, slot)
	if err != nil {
		t.Fatalf("InjectUserNamespace: %v", err)
	}
	if !updated {
		t.Fatal("expected spec to be modified")
	}
	if spec.Linux == nil {
		t.Fatal("spec.Linux is nil after injection")
	}
	foundUserns := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			foundUserns = true
		}
	}
	if !foundUserns {
		t.Error("spec.Linux.Namespaces missing user namespace entry")
	}
	wantUID := c.HostUIDBase + slot*c.RangeSize
	if got := spec.Linux.UIDMappings; len(got) != 1 || got[0].HostID != wantUID || got[0].Size != c.RangeSize || got[0].ContainerID != 0 {
		t.Errorf("UIDMappings = %+v, want one entry [container=0 host=%d size=%d]", got, wantUID, c.RangeSize)
	}
	wantGID := c.HostGIDBase + slot*c.RangeSize
	if got := spec.Linux.GIDMappings; len(got) != 1 || got[0].HostID != wantGID || got[0].Size != c.RangeSize || got[0].ContainerID != 0 {
		t.Errorf("GIDMappings = %+v, want one entry [container=0 host=%d size=%d]", got, wantGID, c.RangeSize)
	}
	if got := spec.Annotations[UserNamespaceSlotAnnotation]; got != "3" {
		t.Errorf("slot annotation = %q, want %q", got, "3")
	}
}

func TestInjectUserNamespaceRespectsCallerMappings(t *testing.T) {
	c := newTestUserNSConfig(t)
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Caller already supplied uidMappings (e.g. kubelet KEP-127 plumbing).
	spec := &specs.Spec{
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{{Type: specs.UserNamespace}},
			UIDMappings: []specs.LinuxIDMapping{
				{ContainerID: 0, HostID: 50000, Size: 1024},
			},
			GIDMappings: []specs.LinuxIDMapping{
				{ContainerID: 0, HostID: 50000, Size: 1024},
			},
		},
	}
	updated, err := InjectUserNamespace(spec, c, 0)
	if err != nil {
		t.Fatalf("InjectUserNamespace: %v", err)
	}
	if updated {
		t.Error("expected no-op when caller supplied mappings, got modification")
	}
	if len(spec.Linux.UIDMappings) != 1 || spec.Linux.UIDMappings[0].HostID != 50000 {
		t.Errorf("caller mappings overwritten: %+v", spec.Linux.UIDMappings)
	}
}

func TestInjectUserNamespaceRejectsOutOfRangeSlot(t *testing.T) {
	c := newTestUserNSConfig(t)
	spec := &specs.Spec{}
	if _, err := InjectUserNamespace(spec, c, c.PoolSize); err == nil {
		t.Error("expected error for slot == PoolSize, got nil")
	}
}

func TestHasUserNamespaceRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
		want bool
	}{
		{name: "nil spec", spec: nil},
		{name: "no annotations", spec: &specs.Spec{}},
		{
			name: "annotation absent",
			spec: &specs.Spec{Annotations: map[string]string{"unrelated": "true"}},
		},
		{
			name: "annotation false",
			spec: &specs.Spec{Annotations: map[string]string{UserNamespaceRequestAnnotation: "false"}},
		},
		{
			name: "annotation truthy non-true value (must be exact)",
			spec: &specs.Spec{Annotations: map[string]string{UserNamespaceRequestAnnotation: "1"}},
		},
		{
			name: "annotation true",
			spec: &specs.Spec{Annotations: map[string]string{UserNamespaceRequestAnnotation: "true"}},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasUserNamespaceRequest(tc.spec); got != tc.want {
				t.Errorf("HasUserNamespaceRequest = %v, want %v", got, tc.want)
			}
		})
	}
}
