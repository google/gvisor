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
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	localLinkAddr  = "\xde\xad\xbe\xef\x56\x78"
	remoteLinkAddr = "\xde\xad\xbe\xef\x12\x34"
	serverPort     = 10001

	defaultMTU        = 65536
	defaultBufferSize = 1500

	// qDisc options
	numQueues = 1
	queueLen  = 1000
)

var (
	localIPv4Address  = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x01"))
	remoteIPv4Address = tcpip.AddrFromSlice([]byte("\x0a\x00\x00\x02"))
)

type stackOptions struct {
	ep               stack.LinkEndpoint
	addr             tcpip.Address
	enablePacketLogs bool
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
	ep := stackOpts.ep
	if stackOpts.enablePacketLogs {
		ep = sniffer.New(stackOpts.ep)
	}
	qDisc := fifo.New(ep, int(numQueues), int(queueLen))
	opts := stack.NICOptions{
		Name:  "eth0",
		QDisc: qDisc,
	}
	if err := st.CreateNICWithOptions(nicID, ep, opts); err != nil {
		return nil, fmt.Errorf("method CreateNICWithOptions(%d, _, %v) failed: %s", nicID, opts, err)
	}

	// Add Protocol Address.
	protocolNum := ipv4.ProtocolNumber
	routeTable := []tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}}
	if stackOpts.addr.Len() == 16 {
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
	st, err := newStackWithOptions(stackOptions{ep: ep, addr: localIPv4Address, enablePacketLogs: false})
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
	st, err := newStackWithOptions(stackOptions{ep: ep, addr: remoteIPv4Address, enablePacketLogs: false})
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
	q, err := sharedmem.NewQueuePair(sharedmem.QueueOptions{})
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
	ctx.clientStk.RemoveNIC(tcpip.NICID(1))
	ctx.serverStk.RemoveNIC(tcpip.NICID(1))
	unix.Close(ctx.peerFDs[0])
	unix.Close(ctx.peerFDs[1])
	ctx.clientStk.Close()
	ctx.serverStk.Close()
	ctx.clientStk.Wait()
	ctx.serverStk.Wait()
}

func makeRequest(serverAddr tcpip.FullAddress, clientStk *stack.Stack) (*http.Response, error) {
	dialFunc := func(address, protocol string) (net.Conn, error) {
		return gonet.DialTCP(clientStk, serverAddr, ipv4.ProtocolNumber)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialFunc,
		},
	}
	// Close idle "keep alive" connections. If any connections remain open after
	// a test ends, DoLeakCheck() will erroneously detect leaked packets.
	defer httpClient.CloseIdleConnections()
	serverURL := fmt.Sprintf("http://[%s]:%d/", net.IP(serverAddr.Addr.AsSlice()), serverAddr.Port)
	response, err := httpClient.Get(serverURL)
	return response, err
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
	var responseString = strings.Repeat("response", 8<<10)
	go func() {
		http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(responseString))
		}))
	}()

	response, err := makeRequest(listenAddr, ctx.clientStk)
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

func TestServerRoundTripStress(t *testing.T) {
	ctx := newTestContext(t)
	defer ctx.cleanup()
	listenAddr := tcpip.FullAddress{Addr: remoteIPv4Address, Port: serverPort}
	l, err := gonet.ListenTCP(ctx.serverStk, listenAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("failed to start TCP Listener: %s", err)
	}
	defer l.Close()
	var responseString = strings.Repeat("response", 8<<10)
	go func() {
		http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(responseString))
		}))
	}()

	var errs errgroup.Group
	for i := 0; i < 1000; i++ {
		errs.Go(func() error {
			response, err := makeRequest(listenAddr, ctx.clientStk)
			if err != nil {
				return fmt.Errorf("httpClient.Get(\"/\") failed: %s", err)
			}
			if got, want := response.StatusCode, http.StatusOK; got != want {
				return fmt.Errorf("unexpected status code got: %d, want: %d", got, want)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				return fmt.Errorf("io.ReadAll(response.Body) failed: %s", err)
			}
			response.Body.Close()
			if got, want := string(body), responseString; got != want {
				return fmt.Errorf("unexpected response got: %s, want: %s", got, want)
			}
			log.Infof("worker: read %d bytes", len(body))
			return nil
		})
	}
	if err := errs.Wait(); err != nil {
		t.Fatalf("request failed: %s", err)
	}
}

func TestServerBulkTransfer(t *testing.T) {
	var payloadSizes = []int{
		512 << 20,  // 512 MiB
		1024 << 20, // 1 GiB
		2048 << 20, // 2 GiB
	}

	for _, payloadSize := range payloadSizes {
		t.Run(fmt.Sprintf("%d bytes", payloadSize), func(t *testing.T) {
			ctx := newTestContext(t)
			defer ctx.cleanup()
			listenAddr := tcpip.FullAddress{Addr: remoteIPv4Address, Port: serverPort}
			l, err := gonet.ListenTCP(ctx.serverStk, listenAddr, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatalf("failed to start TCP Listener: %s", err)
			}
			defer l.Close()

			const chunkSize = 4 << 20 // 4 MiB
			var responseString = strings.Repeat("r", chunkSize)
			go func() {
				http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for done := 0; done < payloadSize; {
						n, err := w.Write([]byte(responseString))
						if err != nil {
							log.Infof("failed to write response : %s", err)
							return
						}
						done += n
					}
				}))
			}()

			response, err := makeRequest(listenAddr, ctx.clientStk)
			if err != nil {
				t.Fatalf("httpClient.Get(\"/\") failed: %s", err)
			}
			if got, want := response.StatusCode, http.StatusOK; got != want {
				t.Fatalf("unexpected status code got: %d, want: %d", got, want)
			}
			n, err := io.Copy(io.Discard, response.Body)
			if err != nil {
				t.Fatalf("io.Copy(io.Discard, response.Body) failed: %s", err)
			}
			response.Body.Close()
			if got, want := int(n), payloadSize; got != want {
				t.Fatalf("unexpected resposne size got: %d, want: %d", got, want)
			}
			log.Infof("read %d bytes", n)
		})
	}

}

func TestClientBulkTransfer(t *testing.T) {
	var payloadSizes = []int{
		512 << 20,  // 512 MiB
		1024 << 20, // 1 GiB
		2048 << 20, // 2 GiB
	}

	for _, payloadSize := range payloadSizes {
		t.Run(fmt.Sprintf("%d bytes", payloadSize), func(t *testing.T) {
			ctx := newTestContext(t)
			defer ctx.cleanup()
			listenAddr := tcpip.FullAddress{Addr: localIPv4Address, Port: serverPort}
			l, err := gonet.ListenTCP(ctx.clientStk, listenAddr, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatalf("failed to start TCP Listener: %s", err)
			}
			defer l.Close()
			const chunkSize = 4 << 20 // 4 MiB
			var responseString = strings.Repeat("r", chunkSize)
			go func() {
				http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for done := 0; done < payloadSize; {
						n, err := w.Write([]byte(responseString))
						if err != nil {
							log.Infof("failed to write response : %s", err)
							return
						}
						done += n
					}
				}))
			}()

			response, err := makeRequest(listenAddr, ctx.serverStk)
			if err != nil {
				t.Fatalf("httpClient.Get(\"/\") failed: %s", err)
			}
			if err != nil {
				t.Fatalf("httpClient.Get(\"/\") failed: %s", err)
			}
			if got, want := response.StatusCode, http.StatusOK; got != want {
				t.Fatalf("unexpected status code got: %d, want: %d", got, want)
			}
			n, err := io.Copy(io.Discard, response.Body)
			if err != nil {
				t.Fatalf("io.Copy(io.Discard, response.Body) failed: %s", err)
			}
			response.Body.Close()
			if got, want := int(n), payloadSize; got != want {
				t.Fatalf("unexpected resposne size got: %d, want: %d", got, want)
			}
			log.Infof("read %d bytes", n)
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
