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

package hostinet

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestRestoreListenersContinuesAfterFailure(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fd)
	})
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr, err := getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}

	s := &Socket{
		family:   unix.AF_INET,
		stype:    linux.SOCK_STREAM,
		protocol: unix.IPPROTO_TCP,
		fd:       -1,
		savedListener: &listenerState{
			addr:    addr,
			backlog: 1,
		},
	}

	restoredListeners.mu.Lock()
	restoredListeners.sockets = []*Socket{s}
	restoredListeners.mu.Unlock()
	restoreListeners()

	if s.fd != -1 {
		t.Errorf("fd after failed listener restore: got %d, want -1", s.fd)
		_ = unix.Close(s.fd)
	}
	if s.savedListener != nil {
		t.Errorf("savedListener after failed listener restore: got %+v, want nil", s.savedListener)
	}
}

// TestReplaceConfigTransfersHostState verifies that ReplaceConfig transfers
// host-derived configuration into a deserialized stack.
func TestReplaceConfigTransfersHostState(t *testing.T) {
	fresh := NewStack()
	if err := fresh.Configure(true /* allowRawSockets */); err != nil {
		t.Fatalf("fresh.Configure: %v", err)
	}
	if fresh.netDevFile == nil {
		t.Fatalf("fresh.netDevFile is nil after Configure")
	}
	freshDev := fresh.netDevFile
	freshSNMP := fresh.netSNMPFile
	freshAllowedLen := len(fresh.allowedSocketTypes)
	freshTCPRecvBufSize := fresh.tcpRecvBufSize
	if len(fresh.allowedSocketTypes) == 0 {
		t.Fatalf("fresh.allowedSocketTypes is empty after Configure(true)")
	}
	t.Cleanup(fresh.Destroy)

	restored := &Stack{}
	restored.ReplaceConfig(fresh)
	t.Cleanup(restored.Destroy)

	if restored.netDevFile != freshDev {
		t.Errorf("netDevFile not transferred: got %v want %v", restored.netDevFile, freshDev)
	}
	if restored.netSNMPFile != freshSNMP {
		t.Errorf("netSNMPFile not transferred: got %v want %v", restored.netSNMPFile, freshSNMP)
	}
	if fresh.netDevFile != nil {
		t.Errorf("fresh.netDevFile not cleared after transfer: %v", fresh.netDevFile)
	}
	if fresh.netSNMPFile != nil {
		t.Errorf("fresh.netSNMPFile not cleared after transfer: %v", fresh.netSNMPFile)
	}
	if !restored.configured {
		t.Errorf("configured not propagated")
	}
	if len(restored.allowedSocketTypes) != freshAllowedLen {
		t.Errorf("allowedSocketTypes len mismatch: got %d want %d",
			len(restored.allowedSocketTypes), freshAllowedLen)
	}
	if restored.tcpRecvBufSize != freshTCPRecvBufSize {
		t.Errorf("tcpRecvBufSize mismatch: got %+v want %+v",
			restored.tcpRecvBufSize, freshTCPRecvBufSize)
	}

	if _, err := restored.netDevFile.Stat(); err != nil {
		t.Errorf("netDevFile.Stat after ReplaceConfig: %v", err)
	}
}

// TestConfigureIdempotent verifies that only the first Configure call takes
// effect.
func TestConfigureIdempotent(t *testing.T) {
	s := NewStack()
	if err := s.Configure(false /* allowRawSockets */); err != nil {
		t.Fatalf("first Configure: %v", err)
	}
	t.Cleanup(s.Destroy)
	firstDev := s.netDevFile
	firstSNMP := s.netSNMPFile
	firstAllowedLen := len(s.allowedSocketTypes)

	if err := s.Configure(true /* allowRawSockets */); err != nil {
		t.Fatalf("second Configure: %v", err)
	}
	if s.netDevFile != firstDev {
		t.Errorf("second Configure reopened netDevFile")
	}
	if s.netSNMPFile != firstSNMP {
		t.Errorf("second Configure reopened netSNMPFile")
	}
	if len(s.allowedSocketTypes) != firstAllowedLen {
		t.Errorf("second Configure mutated allowedSocketTypes: got %d want %d",
			len(s.allowedSocketTypes), firstAllowedLen)
	}
}
