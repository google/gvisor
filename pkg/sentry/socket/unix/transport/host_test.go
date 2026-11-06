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

package transport

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestSCMSenderBeforeSaveIdempotent verifies that calling beforeSave
// on an SCMSender whose host file descriptor is already closed (fd < 0)
// is a safe no-op and does not panic in fdnotifier.RemoveFD.
func TestSCMSenderBeforeSaveIdempotent(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer unix.Close(fds[1])

	q := &waiter.Queue{}
	ep, sysErr := NewSCMSender(fds[0], q, "test-addr")
	if sysErr != nil {
		unix.Close(fds[0])
		t.Fatalf("NewSCMSender failed: %v", sysErr)
	}
	if err := ep.Init(); err != nil {
		unix.Close(fds[0])
		t.Fatalf("Init failed: %v", err)
	}

	// First beforeSave cleans up the host FD and sets ep.fd = -1.
	ep.beforeSave()
	if ep.fd != -1 {
		t.Fatalf("after beforeSave, ep.fd = %d, want -1", ep.fd)
	}

	// Second beforeSave must be idempotent and must not panic on fdnotifier.RemoveFD(-1).
	ep.beforeSave()
}

// TestHostSenderClosedHostReadiness verifies that HostReadiness reports
// hangup and readable events when the host socket is closed (fd < 0) so that pollers
// are notified of EOF / disconnection.
func TestHostSenderClosedHostReadiness(t *testing.T) {
	c := &HostSender{fd: -1}

	mask := waiter.ReadableEvents | waiter.EventHUp | waiter.EventRdHUp | waiter.WritableEvents
	got := c.HostReadiness(mask)
	want := (waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventRdHUp) & mask
	if got != want {
		t.Fatalf("HostReadiness(%v) when fd < 0 = %v, want %v", mask, got, want)
	}

	// A severed socket reports writable.
	if gotOut := c.HostReadiness(waiter.EventOut); gotOut != waiter.EventOut {
		t.Errorf("HostReadiness(EventOut) when fd < 0 = %v, want %v", gotOut, waiter.EventOut)
	}

	// Querying EventHUp explicitly must return EventHUp.
	if gotHup := c.HostReadiness(waiter.EventHUp); gotHup != waiter.EventHUp {
		t.Errorf("HostReadiness(EventHUp) when fd < 0 = %v, want %v", gotHup, waiter.EventHUp)
	}

	// Querying EventIn explicitly must return EventIn.
	if gotIn := c.HostReadiness(waiter.EventIn); gotIn != waiter.EventIn {
		t.Errorf("HostReadiness(EventIn) when fd < 0 = %v, want %v", gotIn, waiter.EventIn)
	}
}

// TestConnectionedEndpointClosedHostReadiness verifies that connectionedEndpoint.Readiness
// properly propagates hangup and readable events when backed by a closed HostSender.
func TestConnectionedEndpointClosedHostReadiness(t *testing.T) {
	c := &HostSender{fd: -1}
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			receiver: c,
			peer:     c,
		},
	}

	mask := waiter.EventIn | waiter.EventHUp | waiter.EventRdHUp | waiter.EventOut
	got := ep.Readiness(mask)
	want := (waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventRdHUp) & mask
	if got != want {
		t.Fatalf("Readiness(%v) for closed host endpoint = %v, want %v", mask, got, want)
	}
}

// TestSeveredRecvSend verifies that an SCMSender whose host fd was severed by
// beforeSave reports EOF on receive and EPIPE on send, never EBADF: the
// application's fd is still valid even though the sentry's host fd is gone.
func TestSeveredRecvSend(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer unix.Close(fds[1])

	ep, serr := NewSCMSender(fds[0], &waiter.Queue{}, "test-addr")
	if serr != nil {
		unix.Close(fds[0])
		t.Fatalf("NewSCMSender failed: %v", serr)
	}
	if err := ep.Init(); err != nil {
		unix.Close(fds[0])
		t.Fatalf("Init failed: %v", err)
	}

	ep.beforeSave()
	if ep.fd != -1 {
		t.Fatalf("after beforeSave, ep.fd = %d, want -1", ep.fd)
	}

	buf := [][]byte{make([]byte, 8)}
	if _, _, serr := ep.Recv(nil, buf, RecvArgs{}); serr != syserr.ErrClosedForReceive {
		t.Errorf("Recv on severed endpoint returned %v, want %v", serr, syserr.ErrClosedForReceive)
	}
	if _, _, serr := ep.Send(nil, [][]byte{{1}}, ControlMessages{}, Address{}); serr != syserr.ErrClosedForSend {
		t.Errorf("Send on severed endpoint returned %v, want %v", serr, syserr.ErrClosedForSend)
	}
}

// TestHostSenderRecvPasscred verifies that Recv on a host socket with
// SO_PASSCRED set delivers data and SCM_RIGHTS FDs. Linux attaches
// SCM_CREDENTIALS to every message on such a socket, which used to make Recv
// fail with EINVAL or truncate the rights (gVisor issue #14594).
func TestHostSenderRecvPasscred(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		stype int
	}{
		{"stream", unix.SOCK_STREAM},
		{"seqpacket", unix.SOCK_SEQPACKET},
		{"dgram", unix.SOCK_DGRAM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, tc.stype, 0)
			if err != nil {
				t.Fatalf("Socketpair failed: %v", err)
			}
			defer unix.Close(fds[1])
			if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				unix.Close(fds[0])
				t.Fatalf("Setsockopt(SO_PASSCRED) failed: %v", err)
			}
			ep, serr := NewSCMSender(fds[0], &waiter.Queue{}, "test-addr")
			if serr != nil {
				unix.Close(fds[0])
				t.Fatalf("NewSCMSender failed: %v", serr)
			}
			// ep holds two references, and the last Release closes fds[0].
			defer ep.Release(ctx)
			defer ep.Release(ctx)
			if err := ep.Init(); err != nil {
				t.Fatalf("Init failed: %v", err)
			}

			recv := func(want byte, numRights int) RecvOutput {
				t.Helper()
				buf := make([]byte, 8)
				out, _, serr := ep.Recv(ctx, [][]byte{buf}, RecvArgs{NumRights: numRights})
				if serr != nil {
					t.Fatalf("Recv(NumRights: %d) failed: %v", numRights, serr)
				}
				if out.RecvLen != 1 || buf[0] != want {
					t.Fatalf("Recv(NumRights: %d) = %q, want %q", numRights, buf[:out.RecvLen], want)
				}
				return out
			}

			// Data and rights.
			if err := unix.Sendmsg(fds[1], []byte{'a'}, unix.UnixRights(fds[1]), nil, 0); err != nil {
				t.Fatalf("Sendmsg failed: %v", err)
			}
			out := recv('a', 1)
			if out.ControlTrunc {
				t.Errorf("Recv with rights set ControlTrunc")
			}
			rights, ok := out.Control.Rights.(*SCMRights)
			if !ok || len(rights.FDs) != 1 {
				t.Fatalf("Recv rights = %+v, want one FD", out.Control.Rights)
			}
			var sent, got unix.Stat_t
			if err := unix.Fstat(fds[1], &sent); err != nil {
				t.Fatalf("Fstat failed: %v", err)
			}
			if err := unix.Fstat(rights.FDs[0], &got); err != nil {
				t.Fatalf("Fstat failed: %v", err)
			}
			if got.Ino != sent.Ino {
				t.Errorf("received FD has inode %d, want %d", got.Ino, sent.Ino)
			}
			rights.Release(ctx)

			// Data only, with room for rights.
			if err := unix.Sendmsg(fds[1], []byte{'b'}, nil, nil, 0); err != nil {
				t.Fatalf("Sendmsg failed: %v", err)
			}
			out = recv('b', 1)
			if out.ControlTrunc {
				t.Errorf("Recv without rights set ControlTrunc")
			}
			if out.Control.Rights != nil {
				t.Errorf("Recv without rights returned rights %+v", out.Control.Rights)
			}

			// Data only, without room for rights.
			if err := unix.Sendmsg(fds[1], []byte{'c'}, nil, nil, 0); err != nil {
				t.Fatalf("Sendmsg failed: %v", err)
			}
			recv('c', 0)
		})
	}
}
