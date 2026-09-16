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

package tcp_test

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	testcontext "gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestTCPMigration(t *testing.T) {
	testCases := []struct {
		name                 string
		allowMigration       bool
		removeConf           bool
		hasRouteAfterRestore bool
		wantOriginalState    tcp.EndpointState
		wantRestoredState    tcp.EndpointState
		expectRestored       bool
	}{
		{
			name:                 "MigrationAllowed_RemoveConf_RouteExists",
			allowMigration:       true,
			removeConf:           true,
			hasRouteAfterRestore: true,
			wantOriginalState:    tcp.StateEstablished,
			wantRestoredState:    tcp.StateEstablished,
			expectRestored:       true,
		},
		{
			name:                 "MigrationDisabled_RemoveConf",
			allowMigration:       false,
			removeConf:           true,
			hasRouteAfterRestore: true,
			wantOriginalState:    tcp.StateError,
			wantRestoredState:    tcp.StateError,
			expectRestored:       true,
		},
		{
			name:                 "MigrationAllowed_RemoveConf_NoRoute",
			allowMigration:       true,
			removeConf:           true,
			hasRouteAfterRestore: false,
			wantOriginalState:    tcp.StateEstablished,
			wantRestoredState:    tcp.StateError,
			expectRestored:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create stack.
			c := testcontext.New(t, e2e.DefaultMTU)
			defer c.Cleanup()

			c.Stack().SetAllowLiveTCPMigration(tc.allowMigration)
			c.Stack().SetRemoveConf(tc.removeConf)

			// Establish connection.
			c.CreateConnected(testcontext.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

			if got, want := tcp.EndpointState(c.EP.State()), tcp.StateEstablished; got != want {
				t.Fatalf("Unexpected endpoint state: want %v, got %v", want, got)
			}

			// Save the stack.
			var buf bytes.Buffer
			saveStats, err := state.Save(context.Background(), &buf, c.Stack())
			if err != nil {
				t.Fatalf("Save failed: %v", err)
			}
			t.Logf("Save stats:\n%s", saveStats.String())

			if got, want := tcp.EndpointState(c.EP.State()), tc.wantOriginalState; got != want {
				t.Fatalf("Unexpected original endpoint state after save: want %v, got %v", want, got)
			}

			// Restore the stack.
			restoredStack := stack.New(stack.Options{
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			})
			restoredStack.SetAllowLiveTCPMigration(tc.allowMigration)
			defer restoredStack.Destroy()

			loadStats, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), restoredStack)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			t.Logf("Load stats:\n%s", loadStats.String())

			if tc.hasRouteAfterRestore {
				// Recreate the NIC 1 with same IP.
				ep := channel.New(1000, e2e.DefaultMTU, "")
				if err := restoredStack.CreateNIC(1, ep); err != nil {
					t.Fatalf("CreateNIC failed: %v", err)
				}
				if err := restoredStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
					Protocol:          header.IPv4ProtocolNumber,
					AddressWithPrefix: testcontext.StackAddrWithPrefix,
				}, stack.AddressProperties{}); err != nil {
					t.Fatalf("AddProtocolAddress failed: %v", err)
				}
				restoredStack.SetRouteTable([]tcpip.Route{
					{
						Destination: header.IPv4EmptySubnet,
						NIC:         1,
					},
				})
			}

			stackType := reflect.TypeOf(restoredStack).Elem()
			sf, ok := stackType.FieldByName("restoredEndpoints")
			if !ok {
				t.Fatalf("Field restoredEndpoints not found")
			}
			offset := sf.Offset
			ptr := unsafe.Pointer(uintptr(unsafe.Pointer(restoredStack)) + offset)
			restoredEndpointsPtr := (*[]stack.RestoredEndpoint)(ptr)
			restoredEndpoints := *restoredEndpointsPtr

			var restoredEP tcpip.Endpoint
			if tc.expectRestored {
				if len(restoredEndpoints) != 1 {
					t.Fatalf("Expected 1 restored endpoint, got %d", len(restoredEndpoints))
				}
				var ok bool
				restoredEP, ok = restoredEndpoints[0].(tcpip.Endpoint)
				if !ok {
					t.Fatalf("Restored endpoint does not implement tcpip.Endpoint")
				}
			} else {
				if len(restoredEndpoints) != 0 {
					t.Fatalf("Expected 0 restored endpoints, got %d", len(restoredEndpoints))
				}
			}

			// Now call Restore.
			restoredStack.Restore()

			if tc.expectRestored {
				got, want := tcp.EndpointState(restoredEP.State()), tc.wantRestoredState
				t.Logf("Subtest %s: got state: %v, want state: %v", tc.name, got, want)
				if got != want {
					t.Fatalf("Unexpected restored endpoint state: want %v, got %v", want, got)
				}
			}
		})
	}
}

// TestRestoreListenWithPreexistingConnection tests that a listening endpoint
// properly enters StateListen and accepts new connections after restore, even
// when the snapshot contained active or lingering connected TCP endpoints (e.g.
// from pre-checkpoint readiness probes) that are terminated upon restore
// without live migration.
func TestRestoreListenWithPreexistingConnection(t *testing.T) {
	testCases := []struct {
		name        string
		setupProbes func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint
	}{
		{
			name: "EstablishedProbeConnection",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				waitEntry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				c.WQ.EventRegister(&waitEntry)
				defer c.WQ.EventUnregister(&waitEntry)

				c.PassiveConnect(100, -1, header.TCPSynOptions{MSS: e2e.DefaultIPv4MSS})

				acceptedEP, _, tcpErr := c.EP.Accept(nil)
				if cmp.Equal(&tcpip.ErrWouldBlock{}, tcpErr) {
					select {
					case <-ch:
						acceptedEP, _, tcpErr = c.EP.Accept(nil)
						if tcpErr != nil {
							t.Fatalf("Accept failed: %v", tcpErr)
						}
					case <-time.After(5 * time.Second):
						t.Fatalf("Timed out waiting for accept")
					}
				} else if tcpErr != nil {
					t.Fatalf("Accept failed: %v", tcpErr)
				}
				return []tcpip.Endpoint{acceptedEP}
			},
		},
		{
			name: "CloseWaitProbeConnection",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				waitEntry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				c.WQ.EventRegister(&waitEntry)
				defer c.WQ.EventUnregister(&waitEntry)

				c.PassiveConnect(100, -1, header.TCPSynOptions{MSS: e2e.DefaultIPv4MSS})

				acceptedEP, _, tcpErr := c.EP.Accept(nil)
				if cmp.Equal(&tcpip.ErrWouldBlock{}, tcpErr) {
					select {
					case <-ch:
						acceptedEP, _, tcpErr = c.EP.Accept(nil)
						if tcpErr != nil {
							t.Fatalf("Accept failed: %v", tcpErr)
						}
					case <-time.After(5 * time.Second):
						t.Fatalf("Timed out waiting for accept")
					}
				} else if tcpErr != nil {
					t.Fatalf("Accept failed: %v", tcpErr)
				}

				// Peer sends FIN to transition server-side accepted endpoint to StateCloseWait.
				c.SendPacket(nil, &testcontext.Headers{
					SrcPort: testcontext.TestPort,
					DstPort: testcontext.StackPort,
					Flags:   header.TCPFlagFin | header.TCPFlagAck,
					SeqNum:  seqnum.Value(testcontext.TestInitialSequenceNumber + 1),
					AckNum:  c.IRS + 1,
					RcvWnd:  30000,
				})

				// Drain the ACK from the server for the FIN.
				b := c.GetPacket()
				b.Release()

				if got, want := tcp.EndpointState(acceptedEP.State()), tcp.StateCloseWait; got != want {
					t.Fatalf("Unexpected probe endpoint state: want %v, got %v", want, got)
				}

				return []tcpip.Endpoint{acceptedEP}
			},
		},
		{
			name: "MultipleProbeConnections",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				waitEntry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				c.WQ.EventRegister(&waitEntry)
				defer c.WQ.EventUnregister(&waitEntry)

				var acceptedEPs []tcpip.Endpoint
				for i := uint16(0); i < 3; i++ {
					srcPort := testcontext.TestPort + i
					iss := seqnum.Value(testcontext.TestInitialSequenceNumber + i*1000)

					// Send SYN.
					synOpts := make([]byte, header.TCPOptionsMaximumSize)
					optOffset := header.EncodeMSSOption(uint32(e2e.DefaultIPv4MSS), synOpts)
					padding := 4 - optOffset%4
					for j := optOffset; j < optOffset+padding; j++ {
						synOpts[j] = header.TCPOptionNOP
					}
					optOffset += padding

					c.SendPacket(nil, &testcontext.Headers{
						SrcPort: srcPort,
						DstPort: testcontext.StackPort,
						Flags:   header.TCPFlagSyn,
						SeqNum:  iss,
						RcvWnd:  30000,
						TCPOpts: synOpts[:optOffset],
					})

					// Receive SYN-ACK.
					b := c.GetPacket()
					tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
					serverISS := seqnum.Value(tcpHdr.SequenceNumber())
					b.Release()

					// Send ACK.
					c.SendPacket(nil, &testcontext.Headers{
						SrcPort: srcPort,
						DstPort: testcontext.StackPort,
						Flags:   header.TCPFlagAck,
						SeqNum:  iss + 1,
						AckNum:  serverISS + 1,
						RcvWnd:  30000,
					})

					acceptedEP, _, tcpErr := c.EP.Accept(nil)
					if cmp.Equal(&tcpip.ErrWouldBlock{}, tcpErr) {
						select {
						case <-ch:
							acceptedEP, _, tcpErr = c.EP.Accept(nil)
							if tcpErr != nil {
								t.Fatalf("Accept probe %d failed: %v", i, tcpErr)
							}
						case <-time.After(5 * time.Second):
							t.Fatalf("Timed out waiting for accept on probe %d", i)
						}
					} else if tcpErr != nil {
						t.Fatalf("Accept probe %d failed: %v", i, tcpErr)
					}
					acceptedEPs = append(acceptedEPs, acceptedEP)
				}
				return acceptedEPs
			},
		},
		{
			name: "HandshakeProbeConnection",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				// Send SYN to create a half-open handshake connection in the accept queue.
				synOpts := make([]byte, header.TCPOptionsMaximumSize)
				optOffset := header.EncodeMSSOption(uint32(e2e.DefaultIPv4MSS), synOpts)
				padding := 4 - optOffset%4
				for j := optOffset; j < optOffset+padding; j++ {
					synOpts[j] = header.TCPOptionNOP
				}
				optOffset += padding

				c.SendPacket(nil, &testcontext.Headers{
					SrcPort: testcontext.TestPort,
					DstPort: testcontext.StackPort,
					Flags:   header.TCPFlagSyn,
					SeqNum:  seqnum.Value(testcontext.TestInitialSequenceNumber),
					RcvWnd:  30000,
					TCPOpts: synOpts[:optOffset],
				})

				// Drain SYN-ACK from server.
				b := c.GetPacket()
				b.Release()

				// Do not send final ACK, leaving the connection in handshake state.
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				orderName := "DefaultOrder"
				if reverse {
					orderName = "ReversedOrder"
				}
				t.Run(orderName, func(t *testing.T) {
					c := testcontext.New(t, e2e.DefaultMTU)
					defer c.Cleanup()

					c.Stack().SetAllowLiveTCPMigration(false)
					c.Stack().SetRemoveConf(true)

					c.Create(-1)
					if err := c.EP.Bind(tcpip.FullAddress{Port: testcontext.StackPort}); err != nil {
						t.Fatalf("Bind failed: %v", err)
					}
					if err := c.EP.Listen(10); err != nil {
						t.Fatalf("Listen failed: %v", err)
					}

					// Establish probe connections.
					probes := tc.setupProbes(t, c)
					for _, probe := range probes {
						defer probe.Close()
					}

					// Save the stack.
					var buf bytes.Buffer
					saveStats, err := state.Save(context.Background(), &buf, c.Stack())
					if err != nil {
						t.Fatalf("Save failed: %v", err)
					}
					t.Logf("Save stats:\n%s", saveStats.String())

					// Restore the stack in a new instance with AllowLiveTCPMigration=false.
					restoredStack := stack.New(stack.Options{
						TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
						NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
					})
					restoredStack.SetAllowLiveTCPMigration(false)
					defer restoredStack.Destroy()

					loadStats, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), restoredStack)
					if err != nil {
						t.Fatalf("Load failed: %v", err)
					}
					t.Logf("Load stats:\n%s", loadStats.String())

					// Recreate NIC 1 with same IP.
					ep := channel.New(1000, e2e.DefaultMTU, "")
					if err := restoredStack.CreateNIC(1, ep); err != nil {
						t.Fatalf("CreateNIC failed: %v", err)
					}
					if err := restoredStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
						Protocol:          header.IPv4ProtocolNumber,
						AddressWithPrefix: testcontext.StackAddrWithPrefix,
					}, stack.AddressProperties{}); err != nil {
						t.Fatalf("AddProtocolAddress failed: %v", err)
					}
					restoredStack.SetRouteTable([]tcpip.Route{
						{
							Destination: header.IPv4EmptySubnet,
							NIC:         1,
						},
					})

					// Inspect restored endpoints before Restore().
					stackType := reflect.TypeOf(restoredStack).Elem()
					sf, ok := stackType.FieldByName("restoredEndpoints")
					if !ok {
						t.Fatalf("Field restoredEndpoints not found")
					}
					offset := sf.Offset
					ptr := unsafe.Pointer(uintptr(unsafe.Pointer(restoredStack)) + offset)
					restoredEndpointsPtr := (*[]stack.RestoredEndpoint)(ptr)
					restoredEndpoints := *restoredEndpointsPtr

					// Mark all non-listen restored endpoints with terminateAtRestore = true to simulate snapshot restore.
					for _, rep := range restoredEndpoints {
						epVal := reflect.ValueOf(rep)
						if epVal.Kind() == reflect.Ptr {
							origStateField := epVal.Elem().FieldByName("origEndpointState")
							if origStateField.IsValid() && origStateField.Uint() != uint64(tcp.StateListen) {
								termField := epVal.Elem().FieldByName("terminateAtRestore")
								if termField.IsValid() {
									// Use unsafe to set unexported field terminateAtRestore
									tf, _ := epVal.Elem().Type().FieldByName("terminateAtRestore")
									tPtr := (*bool)(unsafe.Pointer(uintptr(epVal.UnsafePointer()) + tf.Offset))
									*tPtr = true
								}
							}
						}
					}

					if reverse {
						var reordered []stack.RestoredEndpoint
						for i := len(restoredEndpoints) - 1; i >= 0; i-- {
							reordered = append(reordered, restoredEndpoints[i])
						}
						*restoredEndpointsPtr = reordered
					}

					// Find listening endpoint before Restore() clears s.restoredEndpoints.
					var listenEP tcpip.Endpoint
					for _, rep := range *restoredEndpointsPtr {
						epVal := reflect.ValueOf(rep)
						if epVal.Kind() == reflect.Ptr {
							origStateField := epVal.Elem().FieldByName("origEndpointState")
							if origStateField.IsValid() && origStateField.Uint() == uint64(tcp.StateListen) {
								listenEP = rep.(tcpip.Endpoint)
								break
							}
						}
					}

					if listenEP == nil {
						t.Fatalf("Listening endpoint for port %d not found in restored endpoints", testcontext.StackPort)
					}

					// Call Restore with timeout to detect deadlock.
					restoreDone := make(chan struct{})
					go func() {
						restoredStack.Restore()
						close(restoreDone)
					}()

					select {
					case <-restoreDone:
					case <-time.After(5 * time.Second):
						t.Fatal("Deadlock in Restore(): hung waiting on endpoint restoration")
					}

					// Wait for asynchronous restore loading to complete.
					tcpip.AsyncLoading.Wait()

					// Verify that the listening endpoint is in StateListen and not stuck in StateInitial/StateError.
					if got, want := tcp.EndpointState(listenEP.State()), tcp.StateListen; got != want {
						t.Fatalf("Unexpected listening endpoint state: want %v, got %v", want, got)
					}

					// Try establishing a new connection to the restored listening socket.
					// Inject a SYN packet from a new client port (TestPort+100) to StackPort.
					newClientPort := uint16(testcontext.TestPort + 100)
					clientISS := seqnum.Value(testcontext.TestInitialSequenceNumber + 5000)
					synOpts := make([]byte, header.TCPOptionsMaximumSize)
					optOffset := header.EncodeMSSOption(uint32(e2e.DefaultIPv4MSS), synOpts)
					padding := 4 - optOffset%4
					for i := optOffset; i < optOffset+padding; i++ {
						synOpts[i] = header.TCPOptionNOP
					}
					optOffset += padding

					synHdr := c.BuildSegment(nil, &testcontext.Headers{
						SrcPort: newClientPort,
						DstPort: testcontext.StackPort,
						Flags:   header.TCPFlagSyn,
						SeqNum:  clientISS,
						RcvWnd:  30000,
						TCPOpts: synOpts[:optOffset],
					})
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: synHdr,
					})
					ep.InjectInbound(ipv4.ProtocolNumber, pkt)
					pkt.DecRef()

					// Read response from restoredStack.
					readCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					respPkt := ep.ReadContext(readCtx)
					if respPkt == nil {
						t.Fatalf("Restored listening socket failed to respond to SYN")
					}
					defer respPkt.DecRef()

					respView := respPkt.ToView()
					defer respView.Release()
					checker.IPv4(t, respView, checker.TCP(
						checker.SrcPort(testcontext.StackPort),
						checker.DstPort(newClientPort),
						checker.TCPFlags(header.TCPFlagAck|header.TCPFlagSyn),
						checker.TCPAckNum(uint32(clientISS)+1),
					))
				})
			}
		})
	}
}

func buildTCPSegment(srcAddr, dstAddr tcpip.Address, srcPort, dstPort uint16, seqNum, ackNum seqnum.Value, flags header.TCPFlags, rcvWnd seqnum.Size, payload []byte) buffer.Buffer {
	buf := make([]byte, header.TCPMinimumSize+header.IPv4MinimumSize+len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(tcp.ProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	t := header.TCP(buf[header.IPv4MinimumSize:])
	t.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     uint32(seqNum),
		AckNum:     uint32(ackNum),
		DataOffset: uint8(header.TCPMinimumSize),
		Flags:      flags,
		WindowSize: uint16(rcvWnd),
	})

	xsum := header.PseudoHeaderChecksum(tcp.ProtocolNumber, srcAddr, dstAddr, uint16(len(t)+len(payload)))
	xsum = checksum.Checksum(payload, xsum)
	t.SetChecksum(^t.CalculateChecksum(xsum))

	return buffer.MakeWithData(buf)
}

func connectEndpoint(t *testing.T, s *stack.Stack, linkEP *channel.Endpoint, localIP, peerIP tcpip.Address, peerPort uint16, iss seqnum.Value, wq *waiter.Queue) (tcpip.Endpoint, seqnum.Value, uint16) {
	t.Helper()
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	connectErr := ep.Connect(tcpip.FullAddress{Addr: peerIP, Port: peerPort})
	if _, ok := connectErr.(*tcpip.ErrConnectStarted); !ok {
		t.Fatalf("Connect failed: %v", connectErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pkt := linkEP.ReadContext(ctx)
	if pkt == nil {
		t.Fatalf("Timed out waiting for SYN on linkEP")
	}
	defer pkt.DecRef()

	v := pkt.ToView()
	defer v.Release()

	checker.IPv4(t, v,
		checker.SrcAddr(localIP),
		checker.DstAddr(peerIP),
		checker.TCP(
			checker.DstPort(peerPort),
			checker.TCPFlags(header.TCPFlagSyn),
		),
	)

	tcpHdr := header.TCP(header.IPv4(v.AsSlice()).Payload())
	irs := seqnum.Value(tcpHdr.SequenceNumber())
	localPort := tcpHdr.SourcePort()

	synAck := buildTCPSegment(peerIP, localIP, peerPort, localPort, iss, irs.Add(1), header.TCPFlagSyn|header.TCPFlagAck, 30000, nil)
	pktSynAck := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: synAck,
	})
	defer pktSynAck.DecRef()
	linkEP.InjectInbound(ipv4.ProtocolNumber, pktSynAck)

	ackCtx, ackCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer ackCancel()

	ackPkt := linkEP.ReadContext(ackCtx)
	if ackPkt == nil {
		t.Fatalf("Timed out waiting for ACK on linkEP")
	}
	defer ackPkt.DecRef()

	vAck := ackPkt.ToView()
	defer vAck.Release()

	checker.IPv4(t, vAck,
		checker.SrcAddr(localIP),
		checker.DstAddr(peerIP),
		checker.TCP(
			checker.DstPort(peerPort),
			checker.TCPFlags(header.TCPFlagAck),
			checker.TCPSeqNum(uint32(irs)+1),
			checker.TCPAckNum(uint32(iss)+1),
		),
	)

	select {
	case <-notifyCh:
		if err := ep.LastError(); err != nil {
			t.Fatalf("Unexpected error when connecting: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection notification")
	}

	return ep, irs, localPort
}

func TestTCPMigrationMultiNIC(t *testing.T) {
	// Setup stack with 2 NICs.
	// NIC 1: 10.0.1.1/24 (Subnet 10.0.1.0/24)
	// NIC 2: 192.168.1.1/24 (Subnet 192.168.1.0/24)
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	defer s.Destroy()

	s.SetAllowLiveTCPMigration(true)
	s.SetRemoveConf(true)

	nic1LinkEP := channel.New(1000, e2e.DefaultMTU, "")
	nic2LinkEP := channel.New(1000, e2e.DefaultMTU, "")

	if err := s.CreateNIC(1, nic1LinkEP); err != nil {
		t.Fatalf("CreateNIC(1) failed: %v", err)
	}
	if err := s.CreateNIC(2, nic2LinkEP); err != nil {
		t.Fatalf("CreateNIC(2) failed: %v", err)
	}

	nic1Addr := tcpip.AddrFromSlice([]byte("\x0a\x00\x01\x01")) // 10.0.1.1
	nic2Addr := tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x01")) // 192.168.1.1

	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: nic1Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(1) failed: %v", err)
	}

	if err := s.AddProtocolAddress(2, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: nic2Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(2) failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice([]byte("\x0a\x00\x01\x00")), PrefixLen: 24}.Subnet(),
			NIC:         1,
		},
		{
			Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x00")), PrefixLen: 24}.Subnet(),
			NIC:         2,
		},
	})

	peer1Addr := tcpip.AddrFromSlice([]byte("\x0a\x00\x01\x02")) // 10.0.1.2
	peer2Addr := tcpip.AddrFromSlice([]byte("\xc0\xa8\x01\x02")) // 192.168.1.2

	var wq1, wq2 waiter.Queue
	ep1, _, _ := connectEndpoint(t, s, nic1LinkEP, nic1Addr, peer1Addr, 8080, 10000, &wq1)
	defer ep1.Close()

	ep2, _, _ := connectEndpoint(t, s, nic2LinkEP, nic2Addr, peer2Addr, 9090, 20000, &wq2)
	defer ep2.Close()

	if got, want := tcp.EndpointState(ep1.State()), tcp.StateEstablished; got != want {
		t.Fatalf("ep1 state: want %v, got %v", want, got)
	}
	if got, want := tcp.EndpointState(ep2.State()), tcp.StateEstablished; got != want {
		t.Fatalf("ep2 state: want %v, got %v", want, got)
	}

	// Save the stack.
	var buf bytes.Buffer
	saveStats, err := state.Save(context.Background(), &buf, s)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	t.Logf("Save stats:\n%s", saveStats.String())

	// Restore the stack with IP remapping table.
	restoredStack := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	restoredStack.SetAllowLiveTCPMigration(true)
	defer restoredStack.Destroy()

	remapTable := map[string]string{
		"10.0.1.1":    "10.0.2.1",
		"10.0.1.2":    "10.0.2.2",
		"192.168.1.1": "192.168.2.1",
		"192.168.1.2": "192.168.2.2",
	}
	loadCtx := context.WithValue(context.Background(), stack.CtxRestoreIPRemap, remapTable)

	loadStats, err := state.Load(loadCtx, bytes.NewReader(buf.Bytes()), restoredStack)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	t.Logf("Load stats:\n%s", loadStats.String())

	// Reconfigure restored stack with new subnets.
	// NIC 1: 10.0.2.1/24 (Subnet 10.0.2.0/24)
	// NIC 2: 192.168.2.1/24 (Subnet 192.168.2.0/24)
	restoredNIC1LinkEP := channel.New(1000, e2e.DefaultMTU, "")
	restoredNIC2LinkEP := channel.New(1000, e2e.DefaultMTU, "")

	if err := restoredStack.CreateNIC(1, restoredNIC1LinkEP); err != nil {
		t.Fatalf("restoredStack.CreateNIC(1) failed: %v", err)
	}
	if err := restoredStack.CreateNIC(2, restoredNIC2LinkEP); err != nil {
		t.Fatalf("restoredStack.CreateNIC(2) failed: %v", err)
	}

	newNIC1Addr := tcpip.AddrFromSlice([]byte("\x0a\x00\x02\x01")) // 10.0.2.1
	newNIC2Addr := tcpip.AddrFromSlice([]byte("\xc0\xa8\x02\x01")) // 192.168.2.1

	if err := restoredStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: newNIC1Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("restoredStack.AddProtocolAddress(1) failed: %v", err)
	}

	if err := restoredStack.AddProtocolAddress(2, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: newNIC2Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("restoredStack.AddProtocolAddress(2) failed: %v", err)
	}

	restoredStack.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice([]byte("\x0a\x00\x02\x00")), PrefixLen: 24}.Subnet(),
			NIC:         1,
		},
		{
			Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice([]byte("\xc0\xa8\x02\x00")), PrefixLen: 24}.Subnet(),
			NIC:         2,
		},
	})

	stackType := reflect.TypeOf(restoredStack).Elem()
	sf, ok := stackType.FieldByName("restoredEndpoints")
	if !ok {
		t.Fatalf("Field restoredEndpoints not found")
	}
	offset := sf.Offset
	ptr := unsafe.Pointer(uintptr(unsafe.Pointer(restoredStack)) + offset)
	restoredEndpointsPtr := (*[]stack.RestoredEndpoint)(ptr)
	restoredEndpoints := *restoredEndpointsPtr

	if len(restoredEndpoints) != 2 {
		t.Fatalf("Expected 2 restored endpoints, got %d", len(restoredEndpoints))
	}

	// Restore the stack.
	restoredStack.Restore()

	var restoredEP1, restoredEP2 tcpip.Endpoint
	for i, rep := range restoredEndpoints {
		ep, ok := rep.(tcpip.Endpoint)
		if !ok {
			t.Fatalf("Restored endpoint %d does not implement tcpip.Endpoint", i)
		}
		if got, want := tcp.EndpointState(ep.State()), tcp.StateEstablished; got != want {
			t.Fatalf("Restored endpoint %d state: want %v, got %v", i, want, got)
		}
		info := ep.Info()
		tcpInfo, ok := info.(*stack.TransportEndpointInfo)
		if !ok {
			t.Fatalf("Restored endpoint %d info is not *stack.TransportEndpointInfo, got %T", i, info)
		}
		switch tcpInfo.ID.LocalAddress {
		case newNIC1Addr:
			restoredEP1 = ep
		case newNIC2Addr:
			restoredEP2 = ep
		}
		t.Logf("Restored endpoint %d: state=%v, info=%+v", i, ep.State(), info)
	}

	if restoredEP1 == nil || restoredEP2 == nil {
		t.Fatalf("Could not find both restored endpoints for NIC 1 and NIC 2")
	}

	// Verify restoredEP1 sends packet routed through NIC 1 with remapped IPs (10.0.2.1 -> 10.0.2.2).
	data1 := []byte("hello-from-restored-nic1")
	var r1 bytes.Reader
	r1.Reset(data1)
	if _, err := restoredEP1.Write(&r1, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("restoredEP1.Write failed: %v", err)
	}

	pkt1Ctx, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()
	pkt1 := restoredNIC1LinkEP.ReadContext(pkt1Ctx)
	if pkt1 == nil {
		t.Fatalf("restoredNIC1LinkEP timed out waiting for data from restoredEP1")
	}
	defer pkt1.DecRef()

	v1 := pkt1.ToView()
	defer v1.Release()

	checker.IPv4(t, v1,
		checker.SrcAddr(newNIC1Addr),
		checker.DstAddr(tcpip.AddrFromSlice([]byte("\x0a\x00\x02\x02"))),
		checker.TCP(
			checker.DstPort(8080),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)

	// Verify restoredEP2 sends packet routed through NIC 2 with remapped IPs (192.168.2.1 -> 192.168.2.2).
	data2 := []byte("hello-from-restored-nic2")
	var r2 bytes.Reader
	r2.Reset(data2)
	if _, err := restoredEP2.Write(&r2, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("restoredEP2.Write failed: %v", err)
	}

	pkt2Ctx, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	pkt2 := restoredNIC2LinkEP.ReadContext(pkt2Ctx)
	if pkt2 == nil {
		t.Fatalf("restoredNIC2LinkEP timed out waiting for data from restoredEP2")
	}
	defer pkt2.DecRef()

	v2 := pkt2.ToView()
	defer v2.Release()

	checker.IPv4(t, v2,
		checker.SrcAddr(newNIC2Addr),
		checker.DstAddr(tcpip.AddrFromSlice([]byte("\xc0\xa8\x02\x02"))),
		checker.TCP(
			checker.DstPort(9090),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
		),
	)
}
