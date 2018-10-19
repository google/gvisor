// Copyright 2018 Google LLC
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

package port

import (
	"testing"
)

func TestAllocateHint(t *testing.T) {
	m := New()

	// We can get the hint port.
	p, ok := m.Allocate(0, 1)
	if !ok {
		t.Errorf("m.Allocate got !ok want ok")
	}
	if p != 1 {
		t.Errorf("m.Allocate(0, 1) got %d want 1", p)
	}

	// Hint is taken.
	p, ok = m.Allocate(0, 1)
	if !ok {
		t.Errorf("m.Allocate got !ok want ok")
	}
	if p == 1 {
		t.Errorf("m.Allocate(0, 1) got 1 want anything else")
	}

	// Hint is available for a different protocol.
	p, ok = m.Allocate(1, 1)
	if !ok {
		t.Errorf("m.Allocate got !ok want ok")
	}
	if p != 1 {
		t.Errorf("m.Allocate(1, 1) got %d want 1", p)
	}

	m.Release(0, 1)

	// Hint is available again after release.
	p, ok = m.Allocate(0, 1)
	if !ok {
		t.Errorf("m.Allocate got !ok want ok")
	}
	if p != 1 {
		t.Errorf("m.Allocate(0, 1) got %d want 1", p)
	}
}

func TestAllocateExhausted(t *testing.T) {
	m := New()

	// Fill all ports (0 is already reserved).
	for i := int32(1); i < maxPorts; i++ {
		p, ok := m.Allocate(0, i)
		if !ok {
			t.Fatalf("m.Allocate got !ok want ok")
		}
		if p != i {
			t.Fatalf("m.Allocate(0, %d) got %d want %d", i, p, i)
		}
	}

	// Now no more can be allocated.
	p, ok := m.Allocate(0, 1)
	if ok {
		t.Errorf("m.Allocate got %d, ok want !ok", p)
	}
}
