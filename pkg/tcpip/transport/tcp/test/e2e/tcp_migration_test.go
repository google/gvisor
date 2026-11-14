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

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
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
	acceptProbe := func(t *testing.T, c *testcontext.Context) tcpip.Endpoint {
		t.Helper()
		waitEntry, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
		c.WQ.EventRegister(&waitEntry)
		defer c.WQ.EventUnregister(&waitEntry)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		for {
			ep, _, err := c.EP.Accept(nil)
			if err == nil {
				return ep
			}
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				t.Fatalf("Accept failed: %v", err)
			}
			select {
			case <-ch:
			case <-ctx.Done():
				t.Fatalf("waiting for accept: %v", ctx.Err())
			}
		}
	}

	testCases := []struct {
		name        string
		setupProbes func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint
	}{
		{
			name: "EstablishedProbeConnection",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				c.PassiveConnect(100, -1, header.TCPSynOptions{MSS: e2e.DefaultIPv4MSS})

				acceptedEP := acceptProbe(t, c)
				return []tcpip.Endpoint{acceptedEP}
			},
		},
		{
			name: "CloseWaitProbeConnection",
			setupProbes: func(t *testing.T, c *testcontext.Context) []tcpip.Endpoint {
				c.PassiveConnect(100, -1, header.TCPSynOptions{MSS: e2e.DefaultIPv4MSS})

				acceptedEP := acceptProbe(t, c)

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

					acceptedEPs = append(acceptedEPs, acceptProbe(t, c))
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

type unregisteredClock struct {
	tcpip.Clock
}

func TestSaveAfterRestoreWithReplaceConfig(t *testing.T) {
	c := testcontext.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	const preservedNICID = 10
	preservedIPv4Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 0, 1, 1}),
		PrefixLen: 24,
	}
	preservedIPv6Addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom16([16]byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		PrefixLen: 64,
	}
	preservedEP := channel.New(1000, e2e.DefaultMTU, "")
	defer preservedEP.Close()
	if err := c.Stack().CreateNICWithOptions(preservedNICID, preservedEP, stack.NICOptions{Kind: stack.NICKindTun}); err != nil {
		t.Fatalf("CreateNICWithOptions failed: %v", err)
	}
	if err := c.Stack().AddProtocolAddress(preservedNICID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: preservedIPv4Addr,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(IPv4) failed: %v", err)
	}
	if err := c.Stack().AddProtocolAddress(preservedNICID, tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: preservedIPv6Addr,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(IPv6) failed: %v", err)
	}

	c.Stack().SetRemoveConf(false)

	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, c.Stack()); err != nil {
		t.Fatalf("First Save failed: %v", err)
	}
	c.Stack().Resume()

	restoredStack := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
	})
	defer restoredStack.Destroy()

	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), restoredStack); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Simulate sentry restore creating unpreserved NICs on a temporary stack
	// with a non-state-registered clock before calling ReplaceConfig.
	tempStack := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:              &unregisteredClock{Clock: tcpip.NewStdClock()},
	})
	defer tempStack.Destroy()

	ep := channel.New(1000, e2e.DefaultMTU, "")
	defer ep.Close()
	if err := tempStack.CreateNIC(1, ep); err != nil {
		t.Fatalf("tempStack.CreateNIC failed: %v", err)
	}
	if err := tempStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: testcontext.StackAddrWithPrefix,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("tempStack.AddProtocolAddress(IPv4) failed: %v", err)
	}
	if err := tempStack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          header.IPv6ProtocolNumber,
		AddressWithPrefix: testcontext.StackV6AddrWithPrefix,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("tempStack.AddProtocolAddress(IPv6) failed: %v", err)
	}

	restoredStack.ReplaceConfig(tempStack)
	restoredStack.Restore()

	if got := restoredStack.CheckLocalAddress(preservedNICID, header.IPv4ProtocolNumber, preservedIPv4Addr.Address); got != preservedNICID {
		t.Fatalf("restoredStack.CheckLocalAddress(IPv4) = %d, want %d", got, preservedNICID)
	}
	if got := restoredStack.CheckLocalAddress(preservedNICID, header.IPv6ProtocolNumber, preservedIPv6Addr.Address); got != preservedNICID {
		t.Fatalf("restoredStack.CheckLocalAddress(IPv6) = %d, want %d", got, preservedNICID)
	}

	// Taking a subsequent snapshot with removeConf=false must not serialize
	// unpreserved NICs from tempStack or fail on unregisteredClock.
	restoredStack.SetRemoveConf(false)
	var buf2 bytes.Buffer
	if _, err := state.Save(context.Background(), &buf2, restoredStack); err != nil {
		t.Fatalf("Second Save after Restore+ReplaceConfig failed: %v", err)
	}
	restoredStack.Resume()

	restoredStack2 := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
	})
	defer restoredStack2.Destroy()

	if _, err := state.Load(context.Background(), bytes.NewReader(buf2.Bytes()), restoredStack2); err != nil {
		t.Fatalf("Second Load failed: %v", err)
	}
	restoredStack2.Restore()

	if got := restoredStack2.CheckLocalAddress(preservedNICID, header.IPv4ProtocolNumber, preservedIPv4Addr.Address); got != preservedNICID {
		t.Fatalf("restoredStack2.CheckLocalAddress(IPv4) = %d, want %d", got, preservedNICID)
	}
	if got := restoredStack2.CheckLocalAddress(preservedNICID, header.IPv6ProtocolNumber, preservedIPv6Addr.Address); got != preservedNICID {
		t.Fatalf("restoredStack2.CheckLocalAddress(IPv6) = %d, want %d", got, preservedNICID)
	}
}

func TestTCPMigrationWithGVisorGSO(t *testing.T) {
	for _, tc := range []struct {
		name        string
		srcHostGSO  bool
		dstGSO      stack.SupportedGSO
		wantMinPkts int
	}{
		{
			name:        "NoGSOToGVisorGSO",
			srcHostGSO:  false,
			dstGSO:      stack.GVisorGSOSupported,
			wantMinPkts: 2,
		},
		{
			name:        "HostGSOToNoGSO",
			srcHostGSO:  true,
			dstGSO:      stack.GSONotSupported,
			wantMinPkts: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testcontext.New(t, e2e.DefaultMTU)
			defer c.Cleanup()
			c.SetGSOEnabled(tc.srcHostGSO)

			c.Stack().SetAllowLiveTCPMigration(true)
			c.Stack().SetRemoveConf(true)

			c.CreateConnected(testcontext.TestInitialSequenceNumber, 30000, -1 /* epRcvBuf */)

			var buf bytes.Buffer
			if _, err := state.Save(t.Context(), &buf, c.Stack()); err != nil {
				t.Fatalf("Save failed: %v", err)
			}

			restoredStack := stack.New(stack.Options{
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			})
			restoredStack.SetAllowLiveTCPMigration(true)
			defer restoredStack.Destroy()

			if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), restoredStack); err != nil {
				t.Fatalf("Load failed: %v", err)
			}

			ep := channel.New(1000, e2e.DefaultMTU, "")
			ep.SupportedGSOKind = tc.dstGSO
			defer ep.Close()
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

			restoredStack.Restore()
			eps := restoredStack.RegisteredEndpoints()
			if len(eps) != 1 {
				t.Fatalf("len(restoredStack.RegisteredEndpoints()) = %d, want 1", len(eps))
			}
			restoredEP, ok := eps[0].(tcpip.Endpoint)
			if !ok {
				t.Fatalf("restoredStack.RegisteredEndpoints()[0] = %T, want tcpip.Endpoint", eps[0])
			}

			payload := bytes.Repeat([]byte{'a'}, 2*int(e2e.DefaultMTU))
			var r bytes.Reader
			r.Reset(payload)
			if _, err := restoredEP.Write(&r, tcpip.WriteOptions{}); err != nil {
				t.Fatalf("restoredEP.Write failed: %v", err)
			}
			if got := ep.Drain(); got < tc.wantMinPkts {
				t.Fatalf("ep.Drain() = %d, want >= %d", got, tc.wantMinPkts)
			}
		})
	}
}

func listenTCP(t *testing.T, s *stack.Stack, addr tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue) {
	t.Helper()
	wq := &waiter.Queue{}
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}
	if err := ep.Bind(addr); err != nil {
		t.Fatalf("Bind(%v) failed: %v", addr, err)
	}
	if err := ep.Listen(10); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	return ep, wq
}

func connectAndAcceptTCP(t *testing.T, clientStack *stack.Stack, listenEP tcpip.Endpoint, listenWQ *waiter.Queue, serverAddr tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Endpoint, *waiter.Queue) {
	t.Helper()
	clientWQ := &waiter.Queue{}
	clientEP, err := clientStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, clientWQ)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	writeEntry, writeCh := waiter.NewChannelEntry(waiter.WritableEvents)
	clientWQ.EventRegister(&writeEntry)
	defer clientWQ.EventUnregister(&writeEntry)

	acceptEntry, acceptCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	listenWQ.EventRegister(&acceptEntry)
	defer listenWQ.EventUnregister(&acceptEntry)

	switch err := clientEP.Connect(serverAddr); err.(type) {
	case nil, *tcpip.ErrConnectStarted:
	default:
		t.Fatalf("Connect(%v) failed: %v", serverAddr, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var acceptedEP tcpip.Endpoint
	var acceptedWQ *waiter.Queue
	for acceptedEP == nil {
		var acceptErr tcpip.Error
		acceptedEP, acceptedWQ, acceptErr = listenEP.Accept(nil)
		if acceptErr == nil {
			break
		}
		if _, ok := acceptErr.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Accept failed: %v", acceptErr)
		}
		select {
		case <-acceptCh:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for Accept on %v: %v", serverAddr, ctx.Err())
		}
	}

	for tcp.EndpointState(clientEP.State()) != tcp.StateEstablished {
		select {
		case <-writeCh:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for client endpoint to reach StateEstablished (got %v): %v", tcp.EndpointState(clientEP.State()), ctx.Err())
		}
	}
	return clientEP, clientWQ, acceptedEP, acceptedWQ
}

func writeAndReadAllTCP(t *testing.T, writer tcpip.Endpoint, writerWQ *waiter.Queue, reader tcpip.Endpoint, readerWQ *waiter.Queue, payload []byte) {
	t.Helper()
	writeEntry, writeCh := waiter.NewChannelEntry(waiter.WritableEvents)
	writerWQ.EventRegister(&writeEntry)
	defer writerWQ.EventUnregister(&writeEntry)

	readEntry, readCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	readerWQ.EventRegister(&readEntry)
	defer readerWQ.EventUnregister(&readEntry)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var r bytes.Reader
	r.Reset(payload)
	for r.Len() > 0 {
		_, err := writer.Write(&r, tcpip.WriteOptions{})
		if err == nil {
			continue
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Write failed with %d bytes remaining: %v", r.Len(), err)
		}
		select {
		case <-writeCh:
		case <-ctx.Done():
			t.Fatalf("timed out waiting to write (%d bytes remaining): %v", r.Len(), ctx.Err())
		}
	}

	var got bytes.Buffer
	for got.Len() < len(payload) {
		_, err := reader.Read(&got, tcpip.ReadOptions{})
		if err == nil {
			continue
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Read failed after %d/%d bytes: %v", got.Len(), len(payload), err)
		}
		select {
		case <-readCh:
		case <-ctx.Done():
			t.Fatalf("timed out waiting to read (%d/%d bytes read): %v", got.Len(), len(payload), ctx.Err())
		}
	}

	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read payload len = %d, want %d matching sent payload", got.Len(), len(payload))
	}
}

func TestMultiStackBridgeVethTCPMigration(t *testing.T) {
	const (
		bridgeMAC    = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
		rootVethMAC  = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
		childVethMAC = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x03")

		bridgeID    = tcpip.NICID(1)
		vethRootID  = tcpip.NICID(2)
		loID        = tcpip.NICID(1)
		vethChildID = tcpip.NICID(2)

		rootListenPort  = uint16(8080)
		childListenPort = uint16(9090)
	)

	rootAddr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		PrefixLen: 24,
	}
	childAddr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		PrefixLen: 24,
	}
	subnet := rootAddr.Subnet()

	newStack := func() *stack.Stack {
		return stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
	}

	rootStack := newStack()
	childStack := newStack()
	var preSaveEndpoints []tcpip.Endpoint
	stacksPaused := false
	destroyPreSave := func() {
		if stacksPaused {
			rootStack.Resume()
			childStack.Resume()
			stacksPaused = false
		}
		for _, ep := range preSaveEndpoints {
			ep.Abort()
			ep.Close()
		}
		preSaveEndpoints = nil
		if rootStack != nil {
			rootStack.Destroy()
			rootStack = nil
		}
		if childStack != nil {
			childStack.Destroy()
			childStack = nil
		}
	}
	t.Cleanup(destroyPreSave)

	// Configure rootStack with a bridge (br0) and an enslaved veth port (veth0).
	bridgeEP := stack.NewBridgeEndpoint(e2e.DefaultMTU)
	bridgeEP.SetLinkAddress(bridgeMAC)
	if err := rootStack.CreateNICWithOptions(bridgeID, bridgeEP, stack.NICOptions{Name: "br0", Kind: stack.NICKindBridge}); err != nil {
		t.Fatalf("rootStack.CreateNICWithOptions(br0) failed: %v", err)
	}
	if err := rootStack.AddProtocolAddress(bridgeID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: rootAddr,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("rootStack.AddProtocolAddress(br0) failed: %v", err)
	}
	rootStack.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: bridgeID}})

	vethRoot, vethChild := veth.NewPair(e2e.DefaultMTU, veth.DefaultBacklogSize)
	vethRoot.SetLinkAddress(rootVethMAC)
	vethChild.SetLinkAddress(childVethMAC)

	if err := rootStack.CreateNICWithOptions(vethRootID, ethernet.New(vethRoot), stack.NICOptions{Name: "veth0", Kind: stack.NICKindVeth}); err != nil {
		t.Fatalf("rootStack.CreateNICWithOptions(veth0) failed: %v", err)
	}
	if err := rootStack.SetNICCoordinator(vethRootID, bridgeID); err != nil {
		t.Fatalf("rootStack.SetNICCoordinator(veth0, br0) failed: %v", err)
	}

	// Configure childStack with a preserved loopback NIC and peer veth (eth0).
	if err := childStack.CreateNICWithOptions(loID, loopback.New(), stack.NICOptions{Name: "lo", Preserve: true}); err != nil {
		t.Fatalf("childStack.CreateNICWithOptions(lo) failed: %v", err)
	}
	if err := childStack.CreateNICWithOptions(vethChildID, ethernet.New(vethChild), stack.NICOptions{Name: "eth0", Kind: stack.NICKindVeth}); err != nil {
		t.Fatalf("childStack.CreateNICWithOptions(eth0) failed: %v", err)
	}
	if err := childStack.AddProtocolAddress(vethChildID, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: childAddr,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("childStack.AddProtocolAddress(eth0) failed: %v", err)
	}
	childStack.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: vethChildID}})

	// Create listening and connected TCP endpoints on both stacks across br0 + veth.
	rootServerAddr := tcpip.FullAddress{Addr: rootAddr.Address, Port: rootListenPort}
	childServerAddr := tcpip.FullAddress{Addr: childAddr.Address, Port: childListenPort}

	rootListenEP, rootListenWQ := listenTCP(t, rootStack, rootServerAddr)
	childListenEP, childListenWQ := listenTCP(t, childStack, childServerAddr)
	childClientEP, childClientWQ, rootAcceptedEP, rootAcceptedWQ := connectAndAcceptTCP(t, childStack, rootListenEP, rootListenWQ, rootServerAddr)
	rootClientEP, rootClientWQ, childAcceptedEP, childAcceptedWQ := connectAndAcceptTCP(t, rootStack, childListenEP, childListenWQ, childServerAddr)
	preSaveEndpoints = []tcpip.Endpoint{
		rootListenEP,
		childListenEP,
		childClientEP,
		rootAcceptedEP,
		rootClientEP,
		childAcceptedEP,
	}

	writeAndReadAllTCP(t, childClientEP, childClientWQ, rootAcceptedEP, rootAcceptedWQ, []byte("pre-save-child-to-root"))
	writeAndReadAllTCP(t, rootClientEP, rootClientWQ, childAcceptedEP, childAcceptedWQ, []byte("pre-save-root-to-child"))

	if got := bridgeEP.FindFDBEntry(childVethMAC).PortLinkAddress(); got != rootVethMAC {
		t.Fatalf("bridgeEP.FindFDBEntry(%s) before save = %s, want %s", childVethMAC, got, rootVethMAC)
	}

	// Save both stacks and their endpoints with RemoveConf=true (default
	// AllowLiveTCPMigration=false), exercising BridgeFDBEntry serialization,
	// veth pause/save, and native CapabilitySaveRestore TCP preservation.
	rootStack.SetRemoveConf(true)
	childStack.SetRemoveConf(true)
	rootStack.Pause()
	childStack.Pause()
	stacksPaused = true

	saved := []any{
		rootStack,
		childStack,
		rootListenEP,
		rootListenWQ,
		childListenEP,
		childListenWQ,
		childClientEP,
		childClientWQ,
		rootAcceptedEP,
		rootAcceptedWQ,
		rootClientEP,
		rootClientWQ,
		childAcceptedEP,
		childAcceptedWQ,
	}
	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	destroyPreSave()

	var loaded []any
	if _, err := state.Load(t.Context(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	restoredRoot := loaded[0].(*stack.Stack)
	restoredChild := loaded[1].(*stack.Stack)
	restoredRootListen := loaded[2].(tcpip.Endpoint)
	restoredRootListenWQ := loaded[3].(*waiter.Queue)
	restoredChildListen := loaded[4].(tcpip.Endpoint)
	restoredChildListenWQ := loaded[5].(*waiter.Queue)
	restoredChildClient := loaded[6].(tcpip.Endpoint)
	restoredChildClientWQ := loaded[7].(*waiter.Queue)
	restoredRootAccepted := loaded[8].(tcpip.Endpoint)
	restoredRootAcceptedWQ := loaded[9].(*waiter.Queue)
	restoredRootClient := loaded[10].(tcpip.Endpoint)
	restoredRootClientWQ := loaded[11].(*waiter.Queue)
	restoredChildAccepted := loaded[12].(tcpip.Endpoint)
	restoredChildAcceptedWQ := loaded[13].(*waiter.Queue)

	restoredEndpoints := []tcpip.Endpoint{
		restoredRootListen,
		restoredChildListen,
		restoredChildClient,
		restoredRootAccepted,
		restoredRootClient,
		restoredChildAccepted,
	}
	t.Cleanup(func() {
		for _, ep := range restoredEndpoints {
			ep.Abort()
			ep.Close()
		}
		restoredRoot.Destroy()
		restoredChild.Destroy()
	})

	// Restore both stacks using the two-phase sequence so every stack's
	// connected endpoints finish synchronous restoration before any stack's
	// listening endpoint goroutines wait on connectedLoading.
	restoredRoot.ResetConfig()
	restoreDone := make(chan struct{})
	go func() {
		restoredRoot.RestoreNICsAndEndpoints()
		restoredChild.RestoreNICsAndEndpoints()
		tcpip.AsyncLoading.Wait()
		restoredRoot.RestoreBackgroundWorkers()
		restoredChild.RestoreBackgroundWorkers()
		close(restoreDone)
	}()
	select {
	case <-restoreDone:
	case <-time.After(5 * time.Second):
		t.Fatal("two-phase multi-stack restore deadlocked")
	}

	restoredBridge, ok := restoredRoot.GetLinkEndpointByName("br0").(*stack.BridgeEndpoint)
	if !ok || restoredBridge == nil {
		t.Fatalf("restoredRoot.GetLinkEndpointByName(\"br0\") = %T, want *stack.BridgeEndpoint", restoredRoot.GetLinkEndpointByName("br0"))
	}
	if got := restoredBridge.FindFDBEntry(childVethMAC).PortLinkAddress(); got != rootVethMAC {
		t.Fatalf("restoredBridge.FindFDBEntry(%s) = %s, want %s", childVethMAC, got, rootVethMAC)
	}
	if !restoredChild.HasNIC(loID) {
		t.Fatalf("restoredChild.HasNIC(%d) = false, want true", loID)
	}

	for _, tc := range []struct {
		name string
		ep   tcpip.Endpoint
		want tcp.EndpointState
	}{
		{name: "restoredRootListen", ep: restoredRootListen, want: tcp.StateListen},
		{name: "restoredChildListen", ep: restoredChildListen, want: tcp.StateListen},
		{name: "restoredChildClient", ep: restoredChildClient, want: tcp.StateEstablished},
		{name: "restoredRootAccepted", ep: restoredRootAccepted, want: tcp.StateEstablished},
		{name: "restoredRootClient", ep: restoredRootClient, want: tcp.StateEstablished},
		{name: "restoredChildAccepted", ep: restoredChildAccepted, want: tcp.StateEstablished},
	} {
		if got := tcp.EndpointState(tc.ep.State()); got != tc.want {
			t.Fatalf("%s.State() = %v, want %v", tc.name, got, tc.want)
		}
	}

	// Send >1-MTU payloads on both pre-existing connected TCP pairs to verify
	// restored veth GVisorGSO segmentation (non-zero e.gso.MSS) across br0.
	gsoPayloadChildToRoot := bytes.Repeat([]byte{'c'}, 2*int(e2e.DefaultMTU))
	gsoPayloadRootToChild := bytes.Repeat([]byte{'r'}, 2*int(e2e.DefaultMTU))
	writeAndReadAllTCP(t, restoredChildClient, restoredChildClientWQ, restoredRootAccepted, restoredRootAcceptedWQ, gsoPayloadChildToRoot)
	writeAndReadAllTCP(t, restoredRootClient, restoredRootClientWQ, restoredChildAccepted, restoredChildAcceptedWQ, gsoPayloadRootToChild)

	// Verify both restored listening endpoints accept new connections after restore.
	newChildClient, newChildClientWQ, newRootAccepted, newRootAcceptedWQ := connectAndAcceptTCP(t, restoredChild, restoredRootListen, restoredRootListenWQ, rootServerAddr)
	restoredEndpoints = append(restoredEndpoints, newChildClient, newRootAccepted)
	writeAndReadAllTCP(t, newChildClient, newChildClientWQ, newRootAccepted, newRootAcceptedWQ, []byte("post-restore-new-conn-to-root"))

	newRootClient, newRootClientWQ, newChildAccepted, newChildAcceptedWQ := connectAndAcceptTCP(t, restoredRoot, restoredChildListen, restoredChildListenWQ, childServerAddr)
	restoredEndpoints = append(restoredEndpoints, newRootClient, newChildAccepted)
	writeAndReadAllTCP(t, newRootClient, newRootClientWQ, newChildAccepted, newChildAcceptedWQ, []byte("post-restore-new-conn-to-child"))
}
