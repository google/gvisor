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

package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/refs"
)

// enableLeakPanics makes the leak checker track keys created from now on and
// panic on leaks, until the test ends.
func enableLeakPanics(t *testing.T) {
	t.Helper()
	old := refs.GetLeakMode()
	refs.SetLeakMode(refs.LeaksPanic)
	t.Cleanup(func() { refs.SetLeakMode(old) })
}

// leakCheck runs the leak checker and returns its report, or "" if it found
// no leaks.
func leakCheck() (report string) {
	defer func() {
		if r := recover(); r != nil {
			report = fmt.Sprint(r)
		}
	}()
	refs.DoRepeatedLeakCheck()
	return ""
}

// joinByName takes a reference on the live key named desc in s, as joining a
// session keyring by name does.
func joinByName(t *testing.T, s *KeySet, desc string) *Key {
	t.Helper()
	var found *Key
	s.ForEach(func(k *Key) bool {
		if k.Description == desc && k.TryIncRef() {
			found = k
			return true
		}
		return false
	})
	if found == nil {
		t.Fatalf("no live key named %q", desc)
	}
	return found
}

func addKey(t *testing.T, s *KeySet, creds *Credentials, desc string) *Key {
	t.Helper()
	k, err := s.Add(desc, creds, DefaultNamedSessionKeyringPermissions, MaxSetSize)
	if err != nil {
		t.Fatalf("Add(%q): %v", desc, err)
	}
	return k
}

func checkReleased(t *testing.T, s *KeySet, k *Key) {
	t.Helper()
	if _, err := s.Lookup(k.ID); err != linuxerr.ENOKEY {
		t.Errorf("Lookup(%d) after last DecRef: got err %v, want ENOKEY", k.ID, err)
	}
	if k.TryIncRef() {
		t.Errorf("TryIncRef on key %d succeeded after last DecRef", k.ID)
	}
}

func TestSessionKeyringReferencesDoNotLeak(t *testing.T) {
	enableLeakPanics(t)
	ctx := context.Background()
	ns := NewRootUserNamespace()
	creds := NewRootCredentials(ns)
	s := &ns.Keys

	// Task A joins a new named keyring, and clones task B, which shares it.
	shared := addKey(t, s, creds, "shared")
	shared.IncRef()

	// B joins a new anonymous keyring, dropping its reference on shared.
	anon := addKey(t, s, creds, DefaultSessionKeyringName)
	shared.DecRef(ctx)
	if _, err := s.Lookup(shared.ID); err != nil {
		t.Fatalf("Lookup(%d) while A still holds it: %v", shared.ID, err)
	}

	// B joins shared again by name, which releases anon.
	if got := joinByName(t, s, "shared"); got != shared {
		t.Fatalf("joinByName returned key %d, want %d", got.ID, shared.ID)
	}
	anon.DecRef(ctx)
	checkReleased(t, s, anon)

	// A and B exit.
	shared.DecRef(ctx)
	if _, err := s.Lookup(shared.ID); err != nil {
		t.Fatalf("Lookup(%d) while B still holds it: %v", shared.ID, err)
	}
	shared.DecRef(ctx)
	checkReleased(t, s, shared)

	s.mu.RLock()
	n := len(s.keys)
	s.mu.RUnlock()
	if n != 0 {
		t.Errorf("KeySet holds %d keys after every reference was dropped, want 0", n)
	}
	if report := leakCheck(); report != "" {
		t.Errorf("leak checker reported leaks:\n%s", report)
	}
}

func TestLeakCheckerReportsHeldKey(t *testing.T) {
	enableLeakPanics(t)
	ns := NewRootUserNamespace()
	k := addKey(t, &ns.Keys, NewRootCredentials(ns), "leaked")
	defer k.DecRef(context.Background())

	report := leakCheck()
	want := fmt.Sprintf("[auth.Key %p] reference count of 1", &k.keyRefs)
	if !strings.Contains(report, want) {
		t.Errorf("leak checker report %q does not contain %q", report, want)
	}
}
