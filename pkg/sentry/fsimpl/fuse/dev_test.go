// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"fmt"
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// echoTestOpcode is the Opcode used during testing. The server used in tests
// will simply echo the payload back with the appropriate headers.
const echoTestOpcode linux.FUSEOpcode = 1000

// TestFUSECommunication tests that the communication layer between the Sentry and the
// FUSE server daemon works as expected.
func TestFUSECommunication(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	creds := auth.CredentialsFromContext(s.Ctx)

	// Create test cases with different number of concurrent clients and servers.
	testCases := []struct {
		Name              string
		NumClients        int
		NumServers        int
		MaxActiveRequests uint64
	}{
		{
			Name:              "SingleClientSingleServer",
			NumClients:        1,
			NumServers:        1,
			MaxActiveRequests: maxActiveRequestsDefault,
		},
		{
			Name:              "SingleClientMultipleServers",
			NumClients:        1,
			NumServers:        10,
			MaxActiveRequests: maxActiveRequestsDefault,
		},
		{
			Name:              "MultipleClientsSingleServer",
			NumClients:        10,
			NumServers:        1,
			MaxActiveRequests: maxActiveRequestsDefault,
		},
		{
			Name:              "MultipleClientsMultipleServers",
			NumClients:        10,
			NumServers:        10,
			MaxActiveRequests: maxActiveRequestsDefault,
		},
		{
			Name:              "RequestCapacityFull",
			NumClients:        10,
			NumServers:        1,
			MaxActiveRequests: 1,
		},
		{
			Name:              "RequestCapacityContinuouslyFull",
			NumClients:        100,
			NumServers:        2,
			MaxActiveRequests: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			conn, fd, err := newTestConnection(s, k, testCase.MaxActiveRequests)
			if err != nil {
				t.Fatalf("newTestConnection: %v", err)
			}

			clientsDone := make([]chan struct{}, testCase.NumClients)
			serversDone := make([]chan struct{}, testCase.NumServers)
			serversKill := make([]chan struct{}, testCase.NumServers)

			// FUSE clients.
			for i := 0; i < testCase.NumClients; i++ {
				clientsDone[i] = make(chan struct{})
				go func(i int) {
					fuseClientRun(t, s, k, conn, creds, uint32(i), uint64(i), clientsDone[i])
				}(i)
			}

			// FUSE servers.
			for j := 0; j < testCase.NumServers; j++ {
				serversDone[j] = make(chan struct{})
				serversKill[j] = make(chan struct{}, 1) // The kill command shouldn't block.
				go func(j int) {
					fuseServerRun(t, s, k, fd, serversDone[j], serversKill[j])
				}(j)
			}

			// Tear down.
			//
			// Make sure all the clients are done.
			for i := 0; i < testCase.NumClients; i++ {
				<-clientsDone[i]
			}

			// Kill any server that is potentially waiting.
			for j := 0; j < testCase.NumServers; j++ {
				serversKill[j] <- struct{}{}
			}

			// Make sure all the servers are done.
			for j := 0; j < testCase.NumServers; j++ {
				<-serversDone[j]
			}
		})
	}
}

func TestReuseFd(t *testing.T) {
	s := setup(t)
	defer s.Destroy()
	k := kernel.KernelFromContext(s.Ctx)
	_, fd, err := newTestConnection(s, k, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}
	fs1, err := newTestFilesystem(s, fd, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestFilesystem: %v", err)
	}
	defer fs1.Release(s.Ctx)
	fs2, err := newTestFilesystem(s, fd, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestFilesystem: %v", err)
	}
	defer fs2.Release(s.Ctx)
	if fs1.conn != fs2.conn {
		t.Errorf("second fs connection = %v, want = %v", fs2.conn, fs1.conn)
	}
}

// CallTest makes a request to the server and blocks the invoking
// goroutine until a server responds with a response. Doesn't block
// a kernel.Task. Analogous to Connection.Call but used for testing.
func CallTest(conn *connection, t *kernel.Task, r *Request, i uint32) (*Response, error) {
	conn.fd.mu.Lock()

	// Wait until we're certain that a new request can be processed.
	for conn.fd.numActiveRequests == conn.maxActiveRequests {
		conn.fd.mu.Unlock()
		select {
		case <-conn.fd.fullQueueCh:
		}
		conn.fd.mu.Lock()
	}

	fut, err := conn.callFutureLocked(t, r) // No task given.
	conn.fd.mu.Unlock()

	if err != nil {
		return nil, err
	}

	// Resolve the response.
	//
	// Block without a task.
	select {
	case <-fut.ch:
	}

	// A response is ready. Resolve and return it.
	return fut.getResponse(), nil
}

// ReadTest is analogous to vfs.FileDescription.Read and reads from the FUSE
// device. However, it does so by - not blocking the task that is calling - and
// instead just waits on a channel. The behaviour is essentially the same as
// DeviceFD.Read except it guarantees that the task is not blocked.
func ReadTest(serverTask *kernel.Task, fd *vfs.FileDescription, inIOseq usermem.IOSequence, killServer chan struct{}) (int64, bool, error) {
	var err error
	var n, total int64

	dev := fd.Impl().(*DeviceFD)

	// Register for notifications.
	w, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	dev.EventRegister(&w)
	for {
		// Issue the request and break out if it completes with anything other than
		// "would block".
		n, err = dev.Read(serverTask, inIOseq, vfs.ReadOptions{})
		total += n
		if err != linuxerr.ErrWouldBlock {
			break
		}

		// Wait for a notification that we should retry.
		// Emulate the blocking for when no requests are available
		select {
		case <-ch:
		case <-killServer:
			// Server killed by the main program.
			return 0, true, nil
		}
	}

	dev.EventUnregister(&w)
	return total, false, err
}

// fuseClientRun emulates all the actions of a normal FUSE request. It creates
// a header, a payload, calls the server, waits for the response, and processes
// the response.
func fuseClientRun(t *testing.T, s *testutil.System, k *kernel.Kernel, conn *connection, creds *auth.Credentials, pid uint32, inode uint64, clientDone chan struct{}) {
	defer func() {
		if !t.Failed() {
			clientDone <- struct{}{}
		}
	}()

	tc := k.NewThreadGroup(k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	clientTask, err := testutil.CreateTask(s.Ctx, fmt.Sprintf("fuse-client-%v", pid), tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatal(err)
	}

	testObj := primitive.Uint32(rand.Uint32())
	req := conn.NewRequest(creds, pid, inode, echoTestOpcode, &testObj)

	// Queue up a request.
	// Analogous to Call except it doesn't block on the task.
	resp, err := CallTest(conn, clientTask, req, pid)
	if err != nil {
		t.Fatalf("CallTaskNonBlock failed: %v", err)
	}

	if err = resp.Error(); err != nil {
		t.Fatalf("Server responded with an error: %v", err)
	}

	var respTestPayload primitive.Uint32
	if err := resp.UnmarshalPayload(&respTestPayload); err != nil {
		t.Fatalf("Unmarshalling payload error: %v", err)
	}

	if resp.hdr.Unique != req.hdr.Unique {
		t.Fatalf("got response for another request. Expected response for req %v but got response for req %v",
			req.hdr.Unique, resp.hdr.Unique)
	}

	if respTestPayload != testObj {
		t.Fatalf("read incorrect data. Data expected: %d, but got %d", testObj, respTestPayload)
	}

}

// fuseServerRun creates a task and emulates all the actions of a simple FUSE server
// that simply reads a request and echos the same struct back as a response using the
// appropriate headers.
func fuseServerRun(t *testing.T, s *testutil.System, k *kernel.Kernel, fd *vfs.FileDescription, serverDone, killServer chan struct{}) {
	defer func() {
		if !t.Failed() {
			serverDone <- struct{}{}
		}
	}()

	// Create the tasks that the server will be using.
	tc := k.NewThreadGroup(k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())

	var readPayload primitive.Uint32
	serverTask, err := testutil.CreateTask(s.Ctx, "fuse-server", tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatal(err)
	}

	// Read the request.
	for {
		inHdrLen := uint32((*linux.FUSEHeaderIn)(nil).SizeBytes())
		payloadLen := uint32(readPayload.SizeBytes())

		// The raed buffer must meet some certain size criteria.
		buffSize := inHdrLen + payloadLen
		if buffSize < linux.FUSE_MIN_READ_BUFFER {
			buffSize = linux.FUSE_MIN_READ_BUFFER
		}
		inBuf := make([]byte, buffSize)
		inIOseq := usermem.BytesIOSequence(inBuf)

		n, serverKilled, err := ReadTest(serverTask, fd, inIOseq, killServer)
		if err != nil {
			t.Fatalf("Read failed :%v", err)
		}

		// Server should shut down. No new requests are going to be made.
		if serverKilled {
			break
		}

		if n <= 0 {
			t.Fatalf("Read read no bytes")
		}

		var readFUSEHeaderIn linux.FUSEHeaderIn
		inBuf = readFUSEHeaderIn.UnmarshalUnsafe(inBuf)
		readPayload.UnmarshalUnsafe(inBuf)

		if readFUSEHeaderIn.Opcode != echoTestOpcode {
			t.Fatalf("read incorrect data. Header: %v, Payload: %v", readFUSEHeaderIn, readPayload)
		}

		// Write the response.
		outHdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
		outBuf := make([]byte, outHdrLen+payloadLen)
		outHeader := linux.FUSEHeaderOut{
			Len:    outHdrLen + payloadLen,
			Error:  0,
			Unique: readFUSEHeaderIn.Unique,
		}

		// Echo the payload back.
		outHeader.MarshalUnsafe(outBuf[:outHdrLen])
		readPayload.MarshalUnsafe(outBuf[outHdrLen:])
		outIOseq := usermem.BytesIOSequence(outBuf)

		_, err = fd.Write(s.Ctx, outIOseq, vfs.WriteOptions{})
		if err != nil {
			t.Fatalf("Write failed :%v", err)
		}
	}
}
