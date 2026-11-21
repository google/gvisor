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

//go:build linux
// +build linux

package syserr

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

func TestIsValidMatchesLinuxerr(t *testing.T) {
	var validCount int
	for e := unix.Errno(0); e < maxErrno; e++ {
		if !IsValid(e) {
			continue
		}
		validCount++
		got := linuxerr.ErrorFromUnix(e)
		if got == nil {
			t.Errorf("linuxerr.ErrorFromUnix(%d) = nil, want non-nil", e)
			continue
		}
		le, ok := got.(*errors.Error)
		if !ok {
			t.Errorf("linuxerr.ErrorFromUnix(%d) returned %T, want *errors.Error", e, got)
			continue
		}
		if unix.Errno(le.Errno()) != e {
			t.Errorf("linuxerr.ErrorFromUnix(%d).Errno() = %d, want %d", e, le.Errno(), e)
		}
	}
	if validCount == 0 {
		t.Fatal("IsValid returned false for all errnos")
	}
}
