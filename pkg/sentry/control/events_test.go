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

package control

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gvisor.dev/gvisor/pkg/eventchannel"
	pb "gvisor.dev/gvisor/pkg/eventchannel/eventchannel_go_proto"
	"gvisor.dev/gvisor/pkg/urpc"
)

// attachTestEmitter attaches an emitter with attach and returns a reader for
// the events it writes.
func attachTestEmitter(t *testing.T, attach func(*EventsOpts, *struct{}) error) *bufio.Reader {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	local := os.NewFile(uintptr(fds[0]), "events reader")
	t.Cleanup(func() { local.Close() })
	remote := os.NewFile(uintptr(fds[1]), "events writer")
	defer remote.Close()
	t.Cleanup(func() { eventchannel.DefaultEmitter.Close() })

	if err := attach(&EventsOpts{FilePayload: urpc.FilePayload{Files: []*os.File{remote}}}, nil); err != nil {
		t.Fatalf("attach: %v", err)
	}
	return bufio.NewReader(local)
}

// readEvent reads one event framed as by eventchannel.SocketEmitter.
func readEvent(t *testing.T, r *bufio.Reader) *anypb.Any {
	t.Helper()
	n, err := binary.ReadUvarint(r)
	if err != nil {
		t.Fatalf("reading event length: %v", err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("reading event: %v", err)
	}
	var ev anypb.Any
	if err := proto.Unmarshal(buf, &ev); err != nil {
		t.Fatalf("unmarshaling event: %v", err)
	}
	return &ev
}

func TestAttachRawEmitter(t *testing.T) {
	var e Events
	r := attachTestEmitter(t, e.AttachRawEmitter)

	want := &timestamppb.Timestamp{Seconds: 1234, Nanos: 5678}
	if err := eventchannel.Emit(want); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	ev := readEvent(t, r)
	var got timestamppb.Timestamp
	if err := ev.UnmarshalTo(&got); err != nil {
		t.Fatalf("event has type %q, want %T: %v", ev.GetTypeUrl(), want, err)
	}
	if !proto.Equal(&got, want) {
		t.Errorf("event = %v, want %v", &got, want)
	}
}

func TestAttachDebugEmitter(t *testing.T) {
	var e Events
	r := attachTestEmitter(t, e.AttachDebugEmitter)

	msg := &timestamppb.Timestamp{Seconds: 1234}
	if err := eventchannel.Emit(msg); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	ev := readEvent(t, r)
	var got pb.DebugEvent
	if err := ev.UnmarshalTo(&got); err != nil {
		t.Fatalf("event has type %q, want DebugEvent: %v", ev.GetTypeUrl(), err)
	}
	if want := string(msg.ProtoReflect().Descriptor().FullName()); got.GetName() != want {
		t.Errorf("DebugEvent name = %q, want %q", got.GetName(), want)
	}
}

func TestAttachEmitterReplaces(t *testing.T) {
	var e Events
	old := attachTestEmitter(t, e.AttachRawEmitter)
	r := attachTestEmitter(t, e.AttachRawEmitter)

	if err := eventchannel.Emit(&timestamppb.Timestamp{Seconds: 1234}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	readEvent(t, r)
	if _, err := old.ReadByte(); err != io.EOF {
		t.Errorf("reading replaced emitter = %v, want EOF", err)
	}
}

func TestAttachEmitterRequiresWriter(t *testing.T) {
	var e Events
	for name, attach := range map[string]func(*EventsOpts, *struct{}) error{
		"AttachRawEmitter":   e.AttachRawEmitter,
		"AttachDebugEmitter": e.AttachDebugEmitter,
	} {
		if err := attach(&EventsOpts{}, nil); err == nil {
			t.Errorf("%s with no FD succeeded, want error", name)
		}
	}
}
