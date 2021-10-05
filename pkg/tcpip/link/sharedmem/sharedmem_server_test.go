// Copyright 2021 The gVisor Authors.
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

package sharedmem_server_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	localLinkAddr     = "\xde\xad\xbe\xef\x56\x78"
	remoteLinkAddr    = "\xde\xad\xbe\xef\x12\x34"
	localIPv4Address  = tcpip.Address("\x0a\x00\x00\x01")
	remoteIPv4Address = tcpip.Address("\x0a\x00\x00\x02")
	serverPort        = 10001

	defaultMTU        = 1500
	defaultBufferSize = 1500
)

type stackOptions struct {
	ep   stack.LinkEndpoint
	addr tcpip.Address
}

func newStackWithOptions(stackOpts stackOptions) (*stack.Stack, error) {
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	nicID := tcpip.NICID(1)
	sniffEP := sniffer.New(stackOpts.ep)
	opts := stack.NICOptions{Name: "eth0"}
	if err := st.CreateNICWithOptions(nicID, sniffEP, opts); err != nil {
		return nil, fmt.Errorf("method CreateNICWithOptions(%d, _, %v) failed: %s", nicID, opts, err)
	}

	// Add Protocol Address.
	protocolNum := ipv4.ProtocolNumber
	routeTable := []tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}}
	if len(stackOpts.addr) == 16 {
		routeTable = []tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: nicID}}
		protocolNum = ipv6.ProtocolNumber
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          protocolNum,
		AddressWithPrefix: stackOpts.addr.WithPrefix(),
	}
	if err := st.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("AddProtocolAddress(%d, %v, {}): %s", nicID, protocolAddr, err)
	}

	// Setup route table.
	st.SetRouteTable(routeTable)

	return st, nil
}

func newClientStack(t *testing.T, qPair *sharedmem.QueuePair, peerFD int) (*stack.Stack, error) {
	ep, err := sharedmem.New(sharedmem.Options{
		MTU:         defaultMTU,
		BufferSize:  defaultBufferSize,
		LinkAddress: localLinkAddr,
		TX:          qPair.TXQueueConfig(),
		RX:          qPair.RXQueueConfig(),
		PeerFD:      peerFD,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sharedmem endpoint: %s", err)
	}
	st, err := newStackWithOptions(stackOptions{ep: ep, addr: localIPv4Address})
	if err != nil {
		return nil, fmt.Errorf("failed to create client stack: %s", err)
	}
	return st, nil
}

func newServerStack(t *testing.T, qPair *sharedmem.QueuePair, peerFD int) (*stack.Stack, error) {
	ep, err := sharedmem.NewServerEndpoint(sharedmem.Options{
		MTU:         defaultMTU,
		BufferSize:  defaultBufferSize,
		LinkAddress: remoteLinkAddr,
		TX:          qPair.TXQueueConfig(),
		RX:          qPair.RXQueueConfig(),
		PeerFD:      peerFD,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sharedmem endpoint: %s", err)
	}
	st, err := newStackWithOptions(stackOptions{ep: ep, addr: remoteIPv4Address})
	if err != nil {
		return nil, fmt.Errorf("failed to create client stack: %s", err)
	}
	return st, nil
}

type testContext struct {
	clientStk *stack.Stack
	serverStk *stack.Stack
	peerFDs   [2]int
}

func newTestContext(t *testing.T) *testContext {
	peerFDs, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("failed to create peerFDs: %s", err)
	}
	q, err := sharedmem.NewQueuePair()
	if err != nil {
		t.Fatalf("failed to create sharedmem queue: %s", err)
	}
	clientStack, err := newClientStack(t, q, peerFDs[0])
	if err != nil {
		q.Close()
		unix.Close(peerFDs[0])
		unix.Close(peerFDs[1])
		t.Fatalf("failed to create client stack: %s", err)
	}
	serverStack, err := newServerStack(t, q, peerFDs[1])
	if err != nil {
		q.Close()
		unix.Close(peerFDs[0])
		unix.Close(peerFDs[1])
		clientStack.Close()
		t.Fatalf("failed to create server stack: %s", err)
	}
	return &testContext{
		clientStk: clientStack,
		serverStk: serverStack,
		peerFDs:   peerFDs,
	}
}

func (ctx *testContext) cleanup() {
	unix.Close(ctx.peerFDs[0])
	unix.Close(ctx.peerFDs[1])
	ctx.clientStk.Close()
	ctx.serverStk.Close()
}

func TestServerRoundTrip(t *testing.T) {
	ctx := newTestContext(t)
	defer ctx.cleanup()
	listenAddr := tcpip.FullAddress{Addr: remoteIPv4Address, Port: serverPort}
	l, err := gonet.ListenTCP(ctx.serverStk, listenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("failed to start TCP Listener: %s", err)
	}
	defer l.Close()
	var responseString = "response"
	go func() {
		http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(responseString))
		}))
	}()

	dialFunc := func(address, protocol string) (net.Conn, error) {
		return gonet.DialTCP(ctx.clientStk, listenAddr, ipv4.ProtocolNumber)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialFunc,
		},
	}
	serverURL := fmt.Sprintf("http://[%s]:%d/", net.IP(remoteIPv4Address), serverPort)
	response, err := httpClient.Get(serverURL)
	if err != nil {
		t.Fatalf("httpClient.Get(\"/\") failed: %s", err)
	}
	if got, want := response.StatusCode, http.StatusOK; got != want {
		t.Fatalf("unexpected status code got: %d, want: %d", got, want)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(response.Body) failed: %s", err)
	}
	response.Body.Close()
	if got, want := string(body), responseString; got != want {
		t.Fatalf("unexpected response got: %s, want: %s", got, want)
	}
}
