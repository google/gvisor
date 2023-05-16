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

package istio_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// testContext encapsulates the state required to run tests that simulate
// an istio like environment.
//
// A diagram depicting the setup is shown below.
//
//	+-----------------------------------------------------------------------+
//	| 								+-------------------------------------------------+		 |
//	| + ----------+  | + -----------------+  PROXY      +----------+		|		 |
//	|  | clientEP |  | | serverListeningEP|--accepted-> | serverEP |-+	|		 |
//	| + ----------+ 	| + -----------------+ 	 	 	 	 	 	 +----------+	|	|		 |
//	| 			 	 	|	 	  -------|-------------+ 	 	 	 	     +----------+ | |    |
//	|         	|  					 | 	 	 	 	 	 	 |   	 	 	 	 	 | proxyEP 	|-+	|	 	 |
//	| 				  +-----redirect		 		 		 |						 +----------+	 	|	 	 |
//	|													 					 + ------------+---|------+---+    |
//	|													 					 	 							 	 |  	 	 	 	 	 	 |
//	| 	 	 	 	   	 	 	 	     	 Local Stack.	 	 	 	 	 	 	 	   |               |
//	+-------------------------------------------------------|---------------+
//																													|
//	+-----------------------------------------------------------------------+
//	| 				            remoteStack              	 	 			 | 							 |
//	| 				              +-------------SYN	---------------|   						 |
//	| 				              |                      	 	 	 	 	 |   	 	 	 	 	 	 |
//	| 	+-------------------|--------------------------------|-_---+				 |
//	|  |    + -----------------+              + ----------+ |   	 |				 |
//	| 	|		 | remoteListeningEP|--accepted--->| remoteEP  |<++    |				 |
//	| 	|		 + -----------------+  	 	 	 	 	 	 + ----------+ 	 	 	 |				 |
//	| 	|										Remote HTTP Server 	 	 	 	 	 	 	 	 	 	 |				 |
//	|  +----------------------------------------------------------+				 |
//	+-----------------------------------------------------------------------+
type testContext struct {
	// localServerListener is the listening port for the server which will proxy
	// all traffic to the remote EP.
	localServerListener *gonet.TCPListener

	// remoteListenListener is the remote listening endpoint that will receive
	// connections from server.
	remoteServerListener *gonet.TCPListener

	// localStack is the stack used to create client/server endpoints and
	// also the stack on which we install NAT redirect rules.
	localStack *stack.Stack

	// remoteStack is the stack that represents a *remote* server.
	remoteStack *stack.Stack

	// defaultResponse is the response served by the HTTP server for all GET
	defaultResponse []byte

	// requests.  wg is used to wait for HTTP server and Proxy to terminate before
	// returning from cleanup.
	wg sync.WaitGroup
}

func (ctx *testContext) cleanup() {
	ctx.localServerListener.Close()
	ctx.localStack.Destroy()
	ctx.remoteServerListener.Close()
	ctx.remoteStack.Destroy()
	ctx.wg.Wait()
}

const (
	localServerPort  = 8080
	remoteServerPort = 9090
)

var (
	localIPv4Addr1   = testutil.MustParse4("10.0.0.1")
	localIPv4Addr2   = testutil.MustParse4("10.0.0.2")
	loopbackIPv4Addr = testutil.MustParse4("127.0.0.1")
	remoteIPv4Addr1  = testutil.MustParse4("10.0.0.3")
)

func newTestContext(t *testing.T) *testContext {
	t.Helper()
	localNIC, remoteNIC := pipe.New("" /* linkAddr1 */, "" /* linkAddr2 */, header.IPv4MinimumMTU)

	localStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	remoteStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})

	// Add loopback NIC. We need a loopback NIC as NAT redirect rule redirect to
	// loopback address + specified port.
	loopbackNIC := loopback.New()
	const loopbackNICID = tcpip.NICID(1)
	if err := localStack.CreateNIC(loopbackNICID, sniffer.New(loopbackNIC)); err != nil {
		t.Fatalf("localStack.CreateNIC(%d, _): %s", loopbackNICID, err)
	}
	loopbackAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: loopbackIPv4Addr.WithPrefix(),
	}
	if err := localStack.AddProtocolAddress(loopbackNICID, loopbackAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("localStack.AddProtocolAddress(%d, %+v, {}): %s", loopbackNICID, loopbackAddr, err)
	}

	// Create linked NICs that connects the local and remote stack.
	const localNICID = tcpip.NICID(2)
	const remoteNICID = tcpip.NICID(3)
	if err := localStack.CreateNIC(localNICID, sniffer.New(localNIC)); err != nil {
		t.Fatalf("localStack.CreateNIC(%d, _): %s", localNICID, err)
	}
	if err := remoteStack.CreateNIC(remoteNICID, sniffer.New(remoteNIC)); err != nil {
		t.Fatalf("remoteStack.CreateNIC(%d, _): %s", remoteNICID, err)
	}

	for _, addr := range []tcpip.Address{localIPv4Addr1, localIPv4Addr2} {
		localProtocolAddr := tcpip.ProtocolAddress{
			Protocol:          header.IPv4ProtocolNumber,
			AddressWithPrefix: addr.WithPrefix(),
		}
		if err := localStack.AddProtocolAddress(localNICID, localProtocolAddr, stack.AddressProperties{}); err != nil {
			t.Fatalf("localStack.AddProtocolAddress(%d, %+v, {}): %s", localNICID, localProtocolAddr, err)
		}
	}

	remoteProtocolAddr := tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: remoteIPv4Addr1.WithPrefix(),
	}
	if err := remoteStack.AddProtocolAddress(remoteNICID, remoteProtocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("remoteStack.AddProtocolAddress(%d, %+v, {}): %s", remoteNICID, remoteProtocolAddr, err)
	}

	// Setup route table for local and remote stacks.
	localStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         loopbackNICID,
		},
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         localNICID,
		},
	})
	remoteStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         remoteNICID,
		},
	})

	const netProto = ipv4.ProtocolNumber
	localServerAddress := tcpip.FullAddress{
		Port: localServerPort,
	}

	localServerListener, err := gonet.ListenTCP(localStack, localServerAddress, netProto)
	if err != nil {
		t.Fatalf("gonet.ListenTCP(_, %+v, %d) = %s", localServerAddress, netProto, err)
	}

	remoteServerAddress := tcpip.FullAddress{
		Port: remoteServerPort,
	}
	remoteServerListener, err := gonet.ListenTCP(remoteStack, remoteServerAddress, netProto)
	if err != nil {
		t.Fatalf("gonet.ListenTCP(_, %+v, %d) = %s", remoteServerAddress, netProto, err)
	}

	// Initialize a random default response served by the HTTP server.
	defaultResponse := make([]byte, 512<<10)
	if _, err := rand.Read(defaultResponse); err != nil {
		t.Fatalf("rand.Read(buf) failed: %s", err)
	}

	tc := &testContext{
		localServerListener:  localServerListener,
		remoteServerListener: remoteServerListener,
		localStack:           localStack,
		remoteStack:          remoteStack,
		defaultResponse:      defaultResponse,
	}

	tc.startServers(t)
	return tc
}

func (ctx *testContext) startServers(t *testing.T) {
	ctx.wg.Add(1)
	go func() {
		defer ctx.wg.Done()
		ctx.startHTTPServer()
	}()
	ctx.wg.Add(1)
	go func() {
		defer ctx.wg.Done()
		ctx.startTCPProxyServer(t)
	}()
}

func (ctx *testContext) startTCPProxyServer(t *testing.T) {
	t.Helper()
	for {
		conn, err := ctx.localServerListener.Accept()
		if err != nil {
			t.Logf("terminating local proxy server: %s", err)
			return
		}
		// Start a goroutine to handle this inbound connection.
		go func() {
			remoteServerAddr := tcpip.FullAddress{
				Addr: remoteIPv4Addr1,
				Port: remoteServerPort,
			}
			localServerAddr := tcpip.FullAddress{
				Addr: localIPv4Addr2,
			}
			serverConn, err := gonet.DialTCPWithBind(context.Background(), ctx.localStack, localServerAddr, remoteServerAddr, ipv4.ProtocolNumber)
			if err != nil {
				t.Logf("gonet.DialTCP(_, %+v, %d) =  %s", remoteServerAddr, ipv4.ProtocolNumber, err)
				return
			}
			proxy(conn, serverConn)
			t.Logf("proxying completed")
		}()
	}
}

// proxy transparently proxies the TCP payload from conn1 to conn2
// and vice versa.
func proxy(conn1, conn2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		io.Copy(conn2, conn1)
		conn1.Close()
		conn2.Close()
	}()
	wg.Add(1)
	go func() {
		io.Copy(conn1, conn2)
		conn1.Close()
		conn2.Close()
	}()
	wg.Wait()
}

func (ctx *testContext) startHTTPServer() {
	handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ctx.defaultResponse))
	})
	s := &http.Server{
		Handler: handlerFunc,
	}
	s.Serve(ctx.remoteServerListener)
}

func TestOutboundNATRedirect(t *testing.T) {
	ctx := newTestContext(t)
	defer ctx.cleanup()

	// Install an IPTable rule to redirect all TCP traffic with the sourceIP of
	// localIPv4Addr1 to the tcp proxy port.
	ipt := ctx.localStack.IPTables()
	tbl := ipt.GetTable(stack.NATID, false /* ipv6 */)
	ruleIdx := tbl.BuiltinChains[stack.Output]
	tbl.Rules[ruleIdx].Filter = stack.IPHeaderFilter{
		Protocol:      tcp.ProtocolNumber,
		CheckProtocol: true,
		Src:           localIPv4Addr1,
		SrcMask:       tcpip.AddrFromSlice([]byte("\xff\xff\xff\xff")),
	}
	tbl.Rules[ruleIdx].Target = &stack.RedirectTarget{
		Port:            localServerPort,
		NetworkProtocol: ipv4.ProtocolNumber,
	}
	tbl.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
	ipt.ReplaceTable(stack.NATID, tbl, false /* ipv6 */)

	dialFunc := func(protocol, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("unable to parse address: %s, err: %s", address, err)
		}

		remoteServerIP := net.ParseIP(host)
		remoteServerPort, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("unable to parse port from string %s, err: %s", port, err)
		}
		remoteAddress := tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(remoteServerIP.To4()),
			Port: uint16(remoteServerPort),
		}

		// Dial with an explicit source address bound so that the redirect rule will
		// be able to correctly redirect these packets.
		localAddr := tcpip.FullAddress{Addr: localIPv4Addr1}
		return gonet.DialTCPWithBind(context.Background(), ctx.localStack, localAddr, remoteAddress, ipv4.ProtocolNumber)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialFunc,
		},
	}

	serverURL := fmt.Sprintf("http://[%s]:%d/", net.IP(remoteIPv4Addr1.AsSlice()), remoteServerPort)
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
	if diff := cmp.Diff(body, ctx.defaultResponse); diff != "" {
		t.Fatalf("unexpected response (-want +got): \n %s", diff)
	}
}
