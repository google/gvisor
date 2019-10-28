// Copyright 2019 The gVisor Authors.
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

package muxed

import (
	"bytes"
	"net"
	"os"
	"syscall"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestInjectableEndpointRawDispatch(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t)

	endpoint.InjectOutbound(dstIP, []byte{0xFA})

	buf := make([]byte, ipv4.MaxTotalSize)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}
}

func TestInjectableEndpointDispatch(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t)

	hdr := buffer.NewPrependable(1)
	hdr.Prepend(1)[0] = 0xFA
	packetRoute := stack.Route{RemoteAddress: dstIP}

	endpoint.WritePacket(&packetRoute, nil /* gso */, hdr, buffer.NewViewFromBytes([]byte{0xFB}).ToVectorisedView(), ipv4.ProtocolNumber, stack.DefaultPriority)

	buf := make([]byte, 6500)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA, 0xFB}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}
}

func TestInjectableEndpointDispatchHdrOnly(t *testing.T) {
	endpoint, sock, dstIP := makeTestInjectableEndpoint(t)
	hdr := buffer.NewPrependable(1)
	hdr.Prepend(1)[0] = 0xFA
	packetRoute := stack.Route{RemoteAddress: dstIP}
	endpoint.WritePacket(&packetRoute, nil /* gso */, hdr, buffer.NewView(0).ToVectorisedView(), ipv4.ProtocolNumber, stack.DefaultPriority)
	buf := make([]byte, 6500)
	bytesRead, err := sock.Read(buf)
	if err != nil {
		t.Fatalf("Unable to read from socketpair: %v", err)
	}
	if got, want := buf[:bytesRead], []byte{0xFA}; !bytes.Equal(got, want) {
		t.Fatalf("Read %v from the socketpair, wanted %v", got, want)
	}
}

func makeTestInjectableEndpoint(t *testing.T) (*InjectableEndpoint, *os.File, tcpip.Address) {
	dstIP := tcpip.Address(net.ParseIP("1.2.3.4").To4())
	pair, err := syscall.Socketpair(syscall.AF_UNIX,
		syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal("Failed to create socket pair:", err)
	}
	underlyingEndpoint := fdbased.NewInjectable(pair[1], 6500, stack.CapabilityNone)
	routes := map[tcpip.Address]stack.InjectableLinkEndpoint{dstIP: underlyingEndpoint}
	endpoint := NewInjectableEndpoint(routes)
	return endpoint, os.NewFile(uintptr(pair[0]), "test route end"), dstIP
}
