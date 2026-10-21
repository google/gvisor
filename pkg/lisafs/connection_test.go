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

package connection_test

import (
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

const (
	dynamicMsgID = lisafs.Channel + 1
	versionMsgID = dynamicMsgID + 1
)

var handlers = [...]lisafs.RPCHandler{
	lisafs.Error:   lisafs.ErrorHandler,
	lisafs.Mount:   lisafs.MountHandler,
	lisafs.Channel: lisafs.ChannelHandler,
	dynamicMsgID:   dynamicMsgHandler,
	versionMsgID:   versionHandler,
}

type testControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
}

func (fd *testControlFD) FD() *lisafs.ControlFD {
	return &fd.ControlFD
}

func (fd *testControlFD) Close() {}

// testConnImpl implements lisafs.ConnectionImpl.
type testConnImpl struct{}

var _ lisafs.ConnectionImpl = (*testConnImpl)(nil)

// Mount implements lisafs.ConnectionImpl.Mount.
//
// +checklocksread:c.server.renameMu
// +checklocksexclude:c.fdsMu
func (s *testConnImpl) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, lisafs.Statx, int, error) {
	dummyRoot := &testControlFD{}
	mountNode.IncRef() // Ref is transferred to ControlFD.
	dummyRoot.Init(c, mountNode, linux.ModeDirectory, dummyRoot)
	return dummyRoot.FD(), lisafs.Statx{Mode: uint16(linux.S_IFDIR)}, -1, nil
}

// MaxMessageSize implements lisafs.ConnectionImpl.MaxMessageSize.
func (s *testConnImpl) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

// SupportedMessages implements lisafs.ConnectionImpl.SupportedMessages.
func (s *testConnImpl) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		dynamicMsgID,
		versionMsgID,
	}
}

func runServerClient(t testing.TB, clientFn func(c *lisafs.Client)) {
	runServerClientWithImpl(t, handlers[:], &testConnImpl{}, func(c *lisafs.Client, _ lisafs.Inode) {
		clientFn(c)
	})
}

func runServerClientWithImpl(t testing.TB, handlers []lisafs.RPCHandler, impl lisafs.ConnectionImpl, clientFn func(c *lisafs.Client, root lisafs.Inode)) {
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}

	ts := lisafs.NewServer()
	ts.SetHandlers(handlers)
	conn, err := ts.CreateConnection(serverSocket, "/" /* mountPath */, lisafs.ConnectionOpts{}, impl)
	if err != nil {
		t.Fatalf("starting connection failed: %v", err)
		return
	}
	ts.StartConnection(conn)

	c, root, _, err := lisafs.NewClient(clientSocket)
	if err != nil {
		t.Fatalf("client creation failed: %v", err)
	}
	if err := c.StartChannels(); err != nil {
		t.Fatalf("failed to start channels: %v", err)
	}

	clientFn(c, root)

	c.Close() // This should trigger client and server shutdown.
	ts.Wait()
	ts.Destroy()
}

// TestStartUp tests that the server and client can be started up correctly.
func TestStartUp(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client) {
		if c.IsSupported(lisafs.Error) {
			t.Errorf("sending error messages should not be supported")
		}
	})
}

func TestUnsupportedMessage(t *testing.T) {
	unsupportedM := lisafs.MID(len(handlers))
	var em lisafs.EmptyMessage
	runServerClient(t, func(c *lisafs.Client) {
		if err := c.SndRcvMessage(unsupportedM, uint32(em.SizeBytes()), em.MarshalBytes, em.CheckedUnmarshal, nil, em.String, em.String); err != unix.EOPNOTSUPP {
			t.Errorf("expected EOPNOTSUPP but got err: %v", err)
		}
	})
}

func dynamicMsgHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, error) {
	var req lisafs.MsgDynamic
	if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	// Just echo back the message.
	respPayloadLen := uint32(req.SizeBytes())
	req.MarshalBytes(comm.PayloadBuf(respPayloadLen))
	return respPayloadLen, nil
}

// TestStress stress tests sending many messages from various goroutines.
func TestStress(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client) {
		concurrency := 8
		numMsgPerGoroutine := 5000
		var clientWg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()

				for j := 0; j < numMsgPerGoroutine; j++ {
					// Create a massive random message.
					var req lisafs.MsgDynamic
					req.Randomize(100)

					var resp lisafs.MsgDynamic
					if err := c.SndRcvMessage(dynamicMsgID, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil, req.String, resp.String); err != nil {
						t.Errorf("SndRcvMessage: received unexpected error %v", err)
						return
					}
					if !reflect.DeepEqual(&req, &resp) {
						t.Errorf("response should be the same as request: request = %+v, response = %+v", req, resp)
					}
				}
			}()
		}

		clientWg.Wait()
	})
}

func versionHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, error) {
	// To be fair, usually handlers will create their own objects and return a
	// pointer to those. Might be tempting to reuse above variables, but don't.
	var rv lisafs.P9Version
	if _, ok := rv.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
		return 0, unix.EIO
	}

	// Create a new response.
	sv := lisafs.P9Version{
		MSize:   rv.MSize,
		Version: "9P2000.L.Google.11",
	}
	respPayloadLen := uint32(sv.SizeBytes())
	sv.MarshalBytes(comm.PayloadBuf(respPayloadLen))
	return respPayloadLen, nil
}

// walkTestConnImpl is a testConnImpl that also supports the Walk and Close
// messages, so that tests can serve them with custom handlers.
type walkTestConnImpl struct {
	testConnImpl
}

// SupportedMessages implements lisafs.ConnectionImpl.SupportedMessages.
func (*walkTestConnImpl) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		lisafs.Walk,
		lisafs.Close,
	}
}

// TestWalkMultipleResponseValidation tests that the client rejects Walk
// responses that are inconsistent with the requested path components, and
// closes the control FDs contained in them.
func TestWalkMultipleResponseValidation(t *testing.T) {
	names := []string{"a", "b"}
	for _, tc := range []struct {
		name      string
		status    lisafs.WalkStatus
		numInodes int
		wantErr   error
	}{
		{
			name:      "success",
			status:    lisafs.WalkSuccess,
			numInodes: 2,
		},
		{
			name:      "component does not exist",
			status:    lisafs.WalkComponentDoesNotExist,
			numInodes: 1,
		},
		{
			name:      "first component does not exist",
			status:    lisafs.WalkComponentDoesNotExist,
			numInodes: 0,
		},
		{
			name:      "component symlink",
			status:    lisafs.WalkComponentSymlink,
			numInodes: 1,
		},
		{
			name:      "more inodes than path components",
			status:    lisafs.WalkSuccess,
			numInodes: 3,
			wantErr:   unix.EIO,
		},
		{
			name:      "success with fewer inodes than path components",
			status:    lisafs.WalkSuccess,
			numInodes: 1,
			wantErr:   unix.EIO,
		},
		{
			name:      "component does not exist with all inodes",
			status:    lisafs.WalkComponentDoesNotExist,
			numInodes: 2,
			wantErr:   unix.EIO,
		},
		{
			name:      "component symlink with more inodes than path components",
			status:    lisafs.WalkComponentSymlink,
			numInodes: 3,
			wantErr:   unix.EIO,
		},
		{
			name:      "unknown status",
			status:    lisafs.WalkComponentSymlink + 1,
			numInodes: 1,
			wantErr:   unix.EIO,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inodes := make([]lisafs.Inode, tc.numInodes)
			for i := range inodes {
				inodes[i] = lisafs.Inode{
					ControlFD: lisafs.FDID(100 + i),
					Stat:      lisafs.Statx{Mode: uint16(linux.S_IFDIR)},
				}
			}
			var (
				closedMu sync.Mutex
				closed   = make(map[lisafs.FDID]bool)
			)
			walkHandlers := make([]lisafs.RPCHandler, lisafs.Close+1)
			walkHandlers[lisafs.Error] = lisafs.ErrorHandler
			walkHandlers[lisafs.Mount] = lisafs.MountHandler
			walkHandlers[lisafs.Channel] = lisafs.ChannelHandler
			walkHandlers[lisafs.Walk] = func(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, error) {
				resp := lisafs.WalkResp{Status: tc.status, Inodes: inodes}
				respPayloadLen := uint32(resp.SizeBytes())
				resp.MarshalBytes(comm.PayloadBuf(respPayloadLen))
				return respPayloadLen, nil
			}
			walkHandlers[lisafs.Close] = func(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, error) {
				var req lisafs.CloseReq
				if _, ok := req.CheckedUnmarshal(comm.PayloadBuf(payloadLen)); !ok {
					return 0, unix.EIO
				}
				closedMu.Lock()
				defer closedMu.Unlock()
				for _, fd := range req.FDs {
					closed[fd] = true
				}
				return 0, nil
			}

			runServerClientWithImpl(t, walkHandlers, &walkTestConnImpl{}, func(c *lisafs.Client, root lisafs.Inode) {
				ctx := context.Background()
				rootFD := c.NewFD(root.ControlFD)
				status, gotInodes, err := rootFD.WalkMultiple(ctx, names)
				if err != tc.wantErr {
					t.Errorf("WalkMultiple(%q) error = %v, want %v", names, err, tc.wantErr)
					return
				}
				if err == nil {
					if status != tc.status || len(gotInodes) != tc.numInodes {
						t.Errorf("WalkMultiple(%q) = (status %d, %d inodes), want (status %d, %d inodes)", names, status, len(gotInodes), tc.status, tc.numInodes)
					}
					return
				}
				if len(gotInodes) != 0 {
					t.Errorf("WalkMultiple(%q) returned %d inodes with error, want 0", names, len(gotInodes))
				}
				// Flush the control FDs queued to be closed by WalkMultiple.
				c.CloseFD(ctx, root.ControlFD, true /* flush */)
				closedMu.Lock()
				defer closedMu.Unlock()
				for _, inode := range inodes {
					if !closed[inode.ControlFD] {
						t.Errorf("control FD %d from invalid Walk response was not closed", inode.ControlFD)
					}
				}
			})
		})
	}
}

// BenchmarkSendRecv exists to compete against p9's BenchmarkSendRecvChannel.
func BenchmarkSendRecv(b *testing.B) {
	b.ReportAllocs()
	sendV := lisafs.P9Version{
		MSize:   1 << 20,
		Version: "9P2000.L.Google.12",
	}

	var recvV lisafs.P9Version
	runServerClient(b, func(c *lisafs.Client) {
		for i := 0; i < b.N; i++ {
			if err := c.SndRcvMessage(versionMsgID, uint32(sendV.SizeBytes()), sendV.MarshalBytes, recvV.CheckedUnmarshal, nil, sendV.String, recvV.String); err != nil {
				b.Fatalf("unexpected error occurred: %v", err)
			}
		}
	})
}
