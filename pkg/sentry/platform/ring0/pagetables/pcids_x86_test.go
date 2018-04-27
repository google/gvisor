// Copyright 2018 Google Inc.
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

// +build i386 amd64

package pagetables

import (
	"testing"
)

func TestMaxPCID(t *testing.T) {
	p := NewPCIDs()
	for i := 0; i < maxPCID; i++ {
		if id := p.allocate(); id != uint16(i+1) {
			t.Errorf("got %d, expected %d", id, i+1)
		}
	}
	if id := p.allocate(); id != 0 {
		if id != 0 {
			t.Errorf("got %d, expected 0", id)
		}
	}
}

func TestFirstPCID(t *testing.T) {
	p := NewPCIDs()
	if id := p.allocate(); id != 1 {
		t.Errorf("got %d, expected 1", id)
	}
}

func TestFreePCID(t *testing.T) {
	p := NewPCIDs()
	p.free(0)
	if id := p.allocate(); id != 1 {
		t.Errorf("got %d, expected 1 (not zero)", id)
	}
}

func TestReusePCID(t *testing.T) {
	p := NewPCIDs()
	id := p.allocate()
	if id != 1 {
		t.Errorf("got %d, expected 1", id)
	}
	p.free(id)
	if id := p.allocate(); id != 1 {
		t.Errorf("got %d, expected 1", id)
	}
	if id := p.allocate(); id != 2 {
		t.Errorf("got %d, expected 2", id)
	}
}
