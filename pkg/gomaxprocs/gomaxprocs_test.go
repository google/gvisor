// Copyright 2025 The gVisor Authors.
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

package gomaxprocs

import (
	"runtime"
	"testing"
)

// reset cancels the effect of all previous calls to SetBase and Add and sets
// GOMAXPROCS to the given value.
func reset(n int) {
	mu.Lock()
	defer mu.Unlock()
	base = 0
	temp = 0
	runtime.GOMAXPROCS(n)
}

func TestBasic(t *testing.T) {
	init := runtime.GOMAXPROCS(0)
	defer reset(init)

	firstBase := init + 1
	SetBase(firstBase)
	if got, want := runtime.GOMAXPROCS(0), firstBase; got != want {
		t.Errorf("GOMAXPROCS after first SetBase(%d): got %d, want %d", firstBase, got, want)
	}
	Add(1)
	if got, want := runtime.GOMAXPROCS(0), firstBase+1; got != want {
		t.Errorf("GOMAXPROCS after first Add(1): got %d, want %d", got, want)
	}
	SetBase(firstBase + 1)
	if got, want := runtime.GOMAXPROCS(0), firstBase+2; got != want {
		t.Errorf("GOMAXPROCS after SetBase(%d): got %d, want %d", firstBase+1, got, want)
	}
	Add(1)
	if got, want := runtime.GOMAXPROCS(0), firstBase+3; got != want {
		t.Errorf("GOMAXPROCS after second Add(1): got %d, want %d", got, want)
	}
	SetBase(firstBase)
	if got, want := runtime.GOMAXPROCS(0), firstBase+2; got != want {
		t.Errorf("GOMAXPROCS after second SetBase(%d): got %d, want %d", firstBase, got, want)
	}
	Add(-2)
	if got, want := runtime.GOMAXPROCS(0), firstBase; got != want {
		t.Errorf("GOMAXPROCS after Add(-2): got %d, want %d", got, want)
	}
}

func TestAddIgnoredUntilSetBase(t *testing.T) {
	init := runtime.GOMAXPROCS(0)
	defer reset(init)

	Add(2)
	if got, want := runtime.GOMAXPROCS(0), init; got != want {
		t.Errorf("GOMAXPROCS after Add(2): got %d, want %d", got, want)
	}
	Add(1)
	if got, want := runtime.GOMAXPROCS(0), init; got != want {
		t.Errorf("GOMAXPROCS after Add(1): got %d, want %d", got, want)
	}
	newBase := init + 1
	SetBase(newBase)
	if got, want := runtime.GOMAXPROCS(0), newBase+3; got != want {
		t.Errorf("GOMAXPROCS after SetBase(%d): got %d, want %d", newBase, got, want)
	}
	Add(-3)
	if got, want := runtime.GOMAXPROCS(0), newBase; got != want {
		t.Errorf("GOMAXPROCS after Add(-3): got %d, want %d", got, want)
	}
}
