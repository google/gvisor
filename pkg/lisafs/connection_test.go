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

// testServer implements lisafs.ServerImpl.
type testServer struct {
	lisafs.Server
}

var _ lisafs.ServerImpl = (*testServer)(nil)

type testControlFD struct {
	lisafs.ControlFD
	lisafs.ControlFDImpl
}

func (fd *testControlFD) FD() *lisafs.ControlFD {
	return &fd.ControlFD
}

// Mount implements lisafs.Mount.
func (s *testServer) Mount(c *lisafs.Connection, mountPath string) (lisafs.ControlFDImpl, lisafs.Inode, error) {
	return &testControlFD{}, lisafs.Inode{ControlFD: 1}, nil
}

// MaxMessageSize implements lisafs.MaxMessageSize.
func (s *testServer) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

// SupportedMessages implements lisafs.ServerImpl.SupportedMessages.
func (s *testServer) SupportedMessages() []lisafs.MID {
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		dynamicMsgID,
		versionMsgID,
	}
}

func runServerClient(t testing.TB, clientFn func(c *lisafs.Client)) {
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}

	ts := &testServer{}
	ts.Server.InitTestOnly(ts, handlers[:])
	conn, err := ts.CreateConnection(serverSocket, false /* readonly */)
	if err != nil {
		t.Fatalf("starting connection failed: %v", err)
		return
	}
	ts.StartConnection(conn)

	c, _, err := lisafs.NewClient(clientSocket, "/")
	if err != nil {
		t.Fatalf("client creation failed: %v", err)
	}

	clientFn(c)

	c.Close() // This should trigger client and server shutdown.
	ts.Wait()
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
	runServerClient(t, func(c *lisafs.Client) {
		if err := c.SndRcvMessage(unsupportedM, 0, lisafs.NoopMarshal, lisafs.NoopUnmarshal, nil); err != unix.EOPNOTSUPP {
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
					if err := c.SndRcvMessage(dynamicMsgID, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil); err != nil {
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
			if err := c.SndRcvMessage(versionMsgID, uint32(sendV.SizeBytes()), sendV.MarshalBytes, recvV.CheckedUnmarshal, nil); err != nil {
				b.Fatalf("unexpected error occurred: %v", err)
			}
		}
	})
}
