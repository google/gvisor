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

//go:build amd64
// +build amd64

package fpu

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// newStateForAMX returns a new State, or skips the test if the host can't
// hold AMX state.
func newStateForAMX(t *testing.T) State {
	t.Helper()
	cpuid.Initialize()
	if !cpuid.HostAMXEnabled() {
		t.Skip("host doesn't support AMX")
	}
	return NewState()
}

func setXstateBV(s State, bv uint64) {
	hostarch.ByteOrder.PutUint64(s[xstateBVOffset:], bv)
}

func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

func TestEnableAMX(t *testing.T) {
	s := newStateForAMX(t)
	if s.HasAMX() {
		t.Fatalf("NewState() holds AMX state: len %d", len(s))
	}
	oldLen := len(s)
	prefix := bytes.Clone(s.Slice())
	// Bytes past the length that no XSAVE wrote.
	fill(s[oldLen-FP_XSTATE_MAGIC2_SIZE:cap(s)], 0xff)

	s.EnableAMX()
	if got, want := len(s), AMXStateLen(); got != want {
		t.Fatalf("len after EnableAMX: got %d, want %d", got, want)
	}
	if !s.HasAMX() {
		t.Errorf("HasAMX() = false after EnableAMX")
	}
	if !bytes.Equal(s[:len(prefix)], prefix) {
		t.Errorf("EnableAMX changed the existing state")
	}
	if tail := s[oldLen-FP_XSTATE_MAGIC2_SIZE:]; !bytes.Equal(tail, make([]byte, len(tail))) {
		t.Errorf("EnableAMX didn't clear the bytes past the old length")
	}

	s.EnableAMX()
	if got, want := len(s), AMXStateLen(); got != want {
		t.Errorf("len after second EnableAMX: got %d, want %d", got, want)
	}
}

func TestEnableAMXKeepsSavedTileData(t *testing.T) {
	s := newStateForAMX(t)
	oldLen := len(s)
	// As if XSAVE saved tile data past the length of s.
	setXstateBV(s, hostarch.ByteOrder.Uint64(s[xstateBVOffset:])|cpuid.XCR0AmxDataMask)
	fill(s[oldLen-FP_XSTATE_MAGIC2_SIZE:cap(s)], 0x5a)

	s.EnableAMX()
	tileData := s[oldLen-FP_XSTATE_MAGIC2_SIZE : len(s)-FP_XSTATE_MAGIC2_SIZE]
	if !bytes.Equal(tileData, bytes.Repeat([]byte{0x5a}, len(tileData))) {
		t.Errorf("EnableAMX didn't keep the saved tile data")
	}
}

func TestClearUnusedTileData(t *testing.T) {
	s := newStateForAMX(t)
	defaultLen := len(s)
	s.EnableAMX()
	tileData := s[defaultLen-FP_XSTATE_MAGIC2_SIZE : len(s)-FP_XSTATE_MAGIC2_SIZE]
	bv := hostarch.ByteOrder.Uint64(s[xstateBVOffset:])

	fill(tileData, 0x5a)
	setXstateBV(s, bv|cpuid.XCR0AmxDataMask)
	s.ClearUnusedTileData()
	if !bytes.Equal(tileData, bytes.Repeat([]byte{0x5a}, len(tileData))) {
		t.Errorf("ClearUnusedTileData cleared tile data that is in use")
	}

	setXstateBV(s, bv&^cpuid.XCR0AmxDataMask)
	before := bytes.Clone(s[:defaultLen-FP_XSTATE_MAGIC2_SIZE])
	s.ClearUnusedTileData()
	if !bytes.Equal(tileData, make([]byte, len(tileData))) {
		t.Errorf("ClearUnusedTileData didn't clear unused tile data")
	}
	if !bytes.Equal(s[:len(before)], before) {
		t.Errorf("ClearUnusedTileData changed state other than tile data")
	}

	// State that doesn't hold tile data is unchanged.
	n := NewState()
	setXstateBV(n, bv&^cpuid.XCR0AmxDataMask)
	fill(n[defaultLen-FP_XSTATE_MAGIC2_SIZE:cap(n)], 0x5a)
	n.ClearUnusedTileData()
	if rest := n[defaultLen-FP_XSTATE_MAGIC2_SIZE : cap(n)]; !bytes.Equal(rest, bytes.Repeat([]byte{0x5a}, len(rest))) {
		t.Errorf("ClearUnusedTileData changed state that doesn't hold tile data")
	}
}

func TestSanitizeUserStripsTileData(t *testing.T) {
	s := newStateForAMX(t)
	fs := cpuid.HostFeatureSet()
	bv := hostarch.ByteOrder.Uint64(s[xstateBVOffset:])

	setXstateBV(s, bv|cpuid.XCR0AmxDataMask)
	s.SanitizeUser(fs)
	if got := hostarch.ByteOrder.Uint64(s[xstateBVOffset:]); got&cpuid.XCR0AmxDataMask != 0 {
		t.Errorf("SanitizeUser kept XTILEDATA in state that doesn't hold it: XSTATE_BV %#x", got)
	}

	s.EnableAMX()
	setXstateBV(s, bv|cpuid.XCR0AmxDataMask)
	s.SanitizeUser(fs)
	if got := hostarch.ByteOrder.Uint64(s[xstateBVOffset:]); got&cpuid.XCR0AmxDataMask == 0 {
		t.Errorf("SanitizeUser cleared XTILEDATA in state that holds it: XSTATE_BV %#x", got)
	}
}

func TestAfterLoadAMX(t *testing.T) {
	for _, tc := range []struct {
		name     string
		amx      bool
		tileData bool
		wantAMX  bool
	}{
		{name: "default", wantAMX: false},
		{name: "AMX-sized, tile data unused", amx: true, wantAMX: false},
		{name: "AMX-sized, tile data in use", amx: true, tileData: true, wantAMX: true},
		{name: "default, tile data in use", tileData: true, wantAMX: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStateForAMX(t)
			if tc.amx {
				s.EnableAMX()
			}
			if tc.tileData {
				setXstateBV(s, hostarch.ByteOrder.Uint64(s[xstateBVOffset:])|cpuid.XCR0AmxDataMask)
			}
			s.AfterLoad()
			if got := s.HasAMX(); got != tc.wantAMX {
				t.Errorf("HasAMX() after AfterLoad: got %v, want %v", got, tc.wantAMX)
			}
			bv := hostarch.ByteOrder.Uint64(s[xstateBVOffset:])
			if got, want := bv&cpuid.XCR0AmxDataMask != 0, tc.wantAMX; got != want {
				t.Errorf("XTILEDATA in XSTATE_BV after AfterLoad: got %v, want %v", got, want)
			}
		})
	}
}
