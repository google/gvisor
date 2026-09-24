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
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/inet"
)

func TestRestoreListenersContinuesAfterFailure(t *testing.T) {
	// Socket 1: Will fail to restore because we keep the host socket open,
	// causing EADDRINUSE during bind.
	fd1, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fd1)
	})
	if err := unix.Bind(fd1, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := unix.Listen(fd1, 1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr1, err := getsockname(fd1)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}

	s1 := &Socket{
		family:   unix.AF_INET,
		stype:    linux.SOCK_STREAM,
		protocol: unix.IPPROTO_TCP,
		fd:       -1,
		savedListener: &listenerState{
			addr:    addr1,
			backlog: 1,
		},
	}

	// Socket 2: Will succeed to restore because we close the host socket
	// before restore, freeing the port.
	fd2, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err := unix.Bind(fd2, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 0}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr2, err := getsockname(fd2)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	_ = unix.Close(fd2)

	s2 := &Socket{
		family:   unix.AF_INET,
		stype:    linux.SOCK_STREAM,
		protocol: unix.IPPROTO_TCP,
		fd:       -1,
		savedListener: &listenerState{
			addr:    addr2,
			backlog: 1,
		},
	}

	restoredListeners.mu.Lock()
	restoredListeners.sockets = []*Socket{s1, s2}
	restoredListeners.mu.Unlock()
	restoreListeners()

	// Socket 1 should have failed.
	if s1.fd != -1 {
		t.Errorf("s1.fd after failed restore: got %d, want -1", s1.fd)
		_ = unix.Close(s1.fd)
	}
	if s1.savedListener != nil {
		t.Errorf("s1.savedListener after failed restore: got %+v, want nil", s1.savedListener)
	}

	// Socket 2 should have succeeded.
	if s2.fd == -1 {
		t.Errorf("s2.fd after successful restore: got -1, want valid fd")
	} else {
		_ = unix.Close(s2.fd)
	}
	if s2.savedListener != nil {
		t.Errorf("s2.savedListener after successful restore: got %+v, want nil", s2.savedListener)
	}
}

// TestResetConfigTransfersHostState verifies that ResetConfig configures the
// stack with host state.
func TestResetConfigTransfersHostState(t *testing.T) {
	// Simulate a restored stack by populating some fields.
	restored := &Stack{
		supportsIPv6:    true,
		tcpRecvBufSize:  inet.TCPBufferSize{Min: 1, Default: 2, Max: 3},
		tcpSendBufSize:  inet.TCPBufferSize{Min: 4, Default: 5, Max: 6},
		allowRawSockets: true,
	}
	restored.ResetConfig()
	t.Cleanup(restored.Destroy)

	if !restored.configured {
		t.Errorf("configured: got false, want true")
	}

	devFile, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	snmpFile, err := os.Open("/dev/null")
	if err != nil {
		devFile.Close()
		t.Fatalf("Open: %v", err)
	}
	restored.SetFiles(devFile, snmpFile)

	if restored.netDevFile != devFile {
		t.Errorf("netDevFile: got %v, want %v", restored.netDevFile, devFile)
	}
	if restored.netSNMPFile != snmpFile {
		t.Errorf("netSNMPFile: got %v, want %v", restored.netSNMPFile, snmpFile)
	}

	// Buffer sizes and IPv6 support should be preserved.
	if !restored.supportsIPv6 {
		t.Errorf("supportsIPv6 was lost")
	}
	if restored.tcpRecvBufSize.Default != 2 {
		t.Errorf("tcpRecvBufSize was modified: %+v", restored.tcpRecvBufSize)
	}
	if restored.tcpSendBufSize.Default != 5 {
		t.Errorf("tcpSendBufSize was modified: %+v", restored.tcpSendBufSize)
	}

	wantAllowedLen := len(AllowedSocketTypes) + len(AllowedRawSocketTypes)
	if got := len(restored.allowedSocketTypes); got != wantAllowedLen {
		t.Errorf("allowedSocketTypes len: got %d, want %d", got, wantAllowedLen)
	}

	restored2 := &Stack{
		allowRawSockets: false,
	}
	restored2.ResetConfig()
	wantAllowedLen2 := len(AllowedSocketTypes)
	if got := len(restored2.allowedSocketTypes); got != wantAllowedLen2 {
		t.Errorf("allowedSocketTypes len (no raw): got %d, want %d", got, wantAllowedLen2)
	}
	for _, allowed := range restored2.allowedSocketTypes {
		if allowed.Type == unix.SOCK_RAW {
			t.Errorf("raw socket allowed when allowRawSockets is false: %+v", allowed)
		}
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
