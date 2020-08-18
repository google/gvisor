// Copyright 2018 The gVisor Authors.
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

package p9

import (
	"io/ioutil"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/unet"
)

const (
	MsgTypeBadEncode = iota + 252
	MsgTypeBadDecode
	MsgTypeUnregistered
)

func TestSendRecv(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	defer client.Close()

	if err := send(client, Tag(1), &Tlopen{}); err != nil {
		t.Fatalf("send got err %v expected nil", err)
	}

	tag, m, err := recv(server, maximumLength, msgRegistry.get)
	if err != nil {
		t.Fatalf("recv got err %v expected nil", err)
	}
	if tag != Tag(1) {
		t.Fatalf("got tag %v expected 1", tag)
	}
	if _, ok := m.(*Tlopen); !ok {
		t.Fatalf("got message %v expected *Tlopen", m)
	}
}

// badDecode overruns on decode.
type badDecode struct{}

func (*badDecode) decode(b *buffer) { b.markOverrun() }
func (*badDecode) encode(b *buffer) {}
func (*badDecode) Type() MsgType    { return MsgTypeBadDecode }
func (*badDecode) String() string   { return "badDecode{}" }

func TestRecvOverrun(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	defer client.Close()

	if err := send(client, Tag(1), &badDecode{}); err != nil {
		t.Fatalf("send got err %v expected nil", err)
	}

	if _, _, err := recv(server, maximumLength, msgRegistry.get); err == nil {
		t.Fatalf("recv got err %v expected ErrSocket{ErrNoValidMessage}", err)
	}
}

// unregistered is not registered on decode.
type unregistered struct{}

func (*unregistered) decode(b *buffer) {}
func (*unregistered) encode(b *buffer) {}
func (*unregistered) Type() MsgType    { return MsgTypeUnregistered }
func (*unregistered) String() string   { return "unregistered{}" }

func TestRecvInvalidType(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	defer client.Close()

	if err := send(client, Tag(1), &unregistered{}); err != nil {
		t.Fatalf("send got err %v expected nil", err)
	}

	_, _, err = recv(server, maximumLength, msgRegistry.get)
	if _, ok := err.(*ErrInvalidMsgType); !ok {
		t.Fatalf("recv got err %v expected ErrInvalidMsgType", err)
	}
}

func TestSendRecvWithFile(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	defer client.Close()

	// Create a tempfile.
	osf, err := ioutil.TempFile("", "p9")
	if err != nil {
		t.Fatalf("tempfile got err %v expected nil", err)
	}
	os.Remove(osf.Name())
	f, err := fd.NewFromFile(osf)
	osf.Close()
	if err != nil {
		t.Fatalf("unable to create file: %v", err)
	}

	rlopen := &Rlopen{}
	rlopen.SetFilePayload(f)
	if err := send(client, Tag(1), rlopen); err != nil {
		t.Fatalf("send got err %v expected nil", err)
	}

	// Enable withFile.
	tag, m, err := recv(server, maximumLength, msgRegistry.get)
	if err != nil {
		t.Fatalf("recv got err %v expected nil", err)
	}
	if tag != Tag(1) {
		t.Fatalf("got tag %v expected 1", tag)
	}
	rlopen, ok := m.(*Rlopen)
	if !ok {
		t.Fatalf("got m %v expected *Rlopen", m)
	}
	if rlopen.File == nil {
		t.Fatalf("got nil file expected non-nil")
	}
}

func TestRecvClosed(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	client.Close()

	_, _, err = recv(server, maximumLength, msgRegistry.get)
	if err == nil {
		t.Fatalf("got err nil expected non-nil")
	}
	if _, ok := err.(ErrSocket); !ok {
		t.Fatalf("got err %v expected ErrSocket", err)
	}
}

func TestSendClosed(t *testing.T) {
	server, client, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	server.Close()
	defer client.Close()

	err = send(client, Tag(1), &Tlopen{})
	if err == nil {
		t.Fatalf("send got err nil expected non-nil")
	}
	if _, ok := err.(ErrSocket); !ok {
		t.Fatalf("got err %v expected ErrSocket", err)
	}
}

func BenchmarkSendRecv(b *testing.B) {
	b.ReportAllocs()

	server, client, err := unet.SocketPair(false)
	if err != nil {
		b.Fatalf("socketpair got err %v expected nil", err)
	}
	defer server.Close()
	defer client.Close()

	// Exchange Rflush messages since these contain no data and therefore incur
	// no additional marshaling overhead.
	go func() {
		for i := 0; i < b.N; i++ {
			tag, m, err := recv(server, maximumLength, msgRegistry.get)
			if err != nil {
				b.Fatalf("recv got err %v expected nil", err)
			}
			if tag != Tag(1) {
				b.Fatalf("got tag %v expected 1", tag)
			}
			if _, ok := m.(*Rflush); !ok {
				b.Fatalf("got message %T expected *Rflush", m)
			}
			if err := send(server, Tag(2), &Rflush{}); err != nil {
				b.Fatalf("send got err %v expected nil", err)
			}
		}
	}()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := send(client, Tag(1), &Rflush{}); err != nil {
			b.Fatalf("send got err %v expected nil", err)
		}
		tag, m, err := recv(client, maximumLength, msgRegistry.get)
		if err != nil {
			b.Fatalf("recv got err %v expected nil", err)
		}
		if tag != Tag(2) {
			b.Fatalf("got tag %v expected 2", tag)
		}
		if _, ok := m.(*Rflush); !ok {
			b.Fatalf("got message %v expected *Rflush", m)
		}
	}
}

func init() {
	msgRegistry.register(MsgTypeBadDecode, func() message { return &badDecode{} })
}
