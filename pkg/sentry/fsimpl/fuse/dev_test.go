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
	"io"
	"math/rand"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// echoTestOpcode is the Opcode used during testing. The server used in tests
// will simply echo the payload back with the appropriate headers.
const echoTestOpcode linux.FUSEOpcode = 1000

var testReadMu sync.Mutex
var testCallMu sync.Mutex

type testPayload struct {
	data uint32
}

// TestFUSECommunication tests that the communication layer between the Sentry and the
// FUSE server daemon works as expected.
func TestFUSECommunication(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	creds := auth.CredentialsFromContext(s.Ctx)

	// Create test cases with different number of concurrent clients and servers.
	testCases := []struct {
		Name                string
		NumClients          int
		NumServers          int
		MaxInflightRequests uint64
	}{
		{
			Name:                "SingleClientSingleServer",
			NumClients:          1,
			NumServers:          1,
			MaxInflightRequests: MaxInFlightRequestsDefault,
		},
		{
			Name:                "SingleClientMultipleServers",
			NumClients:          1,
			NumServers:          10,
			MaxInflightRequests: MaxInFlightRequestsDefault,
		},
		{
			Name:                "MultipleClientsSingleServer",
			NumClients:          10,
			NumServers:          1,
			MaxInflightRequests: MaxInFlightRequestsDefault,
		},
		{
			Name:                "MultipleClientsMultipleServers",
			NumClients:          10,
			NumServers:          10,
			MaxInflightRequests: MaxInFlightRequestsDefault,
		},
		{
			Name:                "DelayServerStart",
			NumClients:          10,
			NumServers:          10,
			MaxInflightRequests: MaxInFlightRequestsDefault,
		},
		{
			Name:                "RequestQueueFull",
			NumClients:          10,
			NumServers:          1,
			MaxInflightRequests: 1,
		},
		{
			Name:                "RequestQueueReallyFull",
			NumClients:          100,
			NumServers:          2,
			MaxInflightRequests: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			conn, fd, err := newTestConnection(s, k, testCase.MaxInflightRequests)
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

// CallTest makes a request to the server and blocks the invoking
// goroutine until a server responds with a response. Doesn't block
// a kernel.Task. Analogous to Connection.Call but used for testing.
func CallTest(conn *Connection, t *kernel.Task, r *Request) (*Response, error) {
	// A lock is needed so to make sure that there is no interrupt in between
	// receiving a signal, putting it back and the callFuture call blocking on
	// it. This way we can guarantee that callFuture doesn't block.
	testCallMu.Lock()

	// This request needs to block until we know the queue is no longer full.
	dev := conn.fd

	// Emulate the blocking for when no requests are available. We can't really
	// block a task during test and so this way we guarantee the fast path of
	// task.Block() (when no wait is required) is hit.
	waitChan := dev.fullQueueCh
	select {
	case <-waitChan:
		// Make sure there is something for Read to find.
		waitChan <- struct{}{}
	}

	fut, err := conn.callFuture(t, r) // No task given.
	testCallMu.Unlock()

	if err != nil {
		return nil, err
	}

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

	// A lock is needed to guarantee that if a server is woken up (a request is
	// available), then that server will process the request. We can't have another
	// server running in parallel barge in and serve the request as that would cause
	// the serverTask to block when Read is called below. This is needed only during
	// testing - when actually running FUSE in gVisor, we don't need to avoid
	// blocking the task.
	testReadMu.Lock()
	defer testReadMu.Unlock()

	dev := fd.Impl().(*DeviceFD)
	// Emulate the blocking for when no requests are available. We can't really
	// block a task during test and so this way we guarantee the fast path of
	// task.Block() (when no wait is required) is hit.
	waitChan := dev.emptyQueueCh
	select {
	case <-waitChan:
		// Make sure there is something for Read to find.
		waitChan <- struct{}{}
	case <-killServer:
		// Server killed by the main program.
		return 0, true, nil
	}

	// Perform a non blocking read.
	n, err := fd.Read(serverTask, inIOseq, vfs.ReadOptions{})
	return n, false, err
}

// fuseClientRun emulates all the actions of a normal FUSE request. It creates
// a header, a payload, calls the server, waits for the response, and processes
// the response.
func fuseClientRun(t *testing.T, s *testutil.System, k *kernel.Kernel, conn *Connection, creds *auth.Credentials, pid uint32, inode uint64, clientDone chan struct{}) {
	defer func() { clientDone <- struct{}{} }()

	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	clientTask, err := testutil.CreateTask(s.Ctx, fmt.Sprintf("fuse-client-%v", pid), tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatal(err)
	}
	testObj := &testPayload{
		data: rand.Uint32(),
	}

	req, err := conn.NewRequest(creds, pid, inode, echoTestOpcode, testObj)
	if err != nil {
		t.Fatalf("NewRequest creation failed: %v", err)
	}

	// Queue up a request.
	// Analogous to Call except it doesn't block on the task.
	resp, err := CallTest(conn, clientTask, req)
	if err != nil {
		t.Fatalf("CallTaskNonBlock failed: %v", err)
	}

	if err = resp.Error(); err != nil {
		t.Fatalf("Server responded with an error: %v", err)
	}

	var respTestPayload testPayload
	if err := resp.UnmarshalPayload(&respTestPayload); err != nil {
		t.Fatalf("Unmarshalling payload error: %v", err)
	}

	if resp.hdr.Unique != req.hdr.Unique {
		t.Fatalf("got response for another request. Expected response for req %v but got response for req %v",
			req.hdr.Unique, resp.hdr.Unique)
	}

	if respTestPayload.data != testObj.data {
		t.Fatalf("read incorrect data. Data expected: %v, but got %v", testObj.data, respTestPayload.data)
	}

}

// fuseServerRun creates a task and emulates all the actions of a simple FUSE server
// that simply reads a request and echos the same struct back as a response using the
// appropriate headers.
func fuseServerRun(t *testing.T, s *testutil.System, k *kernel.Kernel, fd *vfs.FileDescription, serverDone, killServer chan struct{}) {
	defer func() { serverDone <- struct{}{} }()

	// Create the tasks that the server will be using.
	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	var readPayload testPayload

	serverTask, err := testutil.CreateTask(s.Ctx, "fuse-server", tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatal(err)
	}

	// Read the request.
	for {
		inHdrLen := uint32((*linux.FUSEHeaderIn)(nil).SizeBytes())
		payloadLen := uint32(readPayload.SizeBytes())
		inBuf := make([]byte, inHdrLen+payloadLen)
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
		readFUSEHeaderIn.UnmarshalUnsafe(inBuf[:inHdrLen])
		readPayload.UnmarshalUnsafe(inBuf[inHdrLen:])

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

		n, err = fd.Write(s.Ctx, outIOseq, vfs.WriteOptions{})
		if err != nil {
			t.Fatalf("Write failed :%v", err)
		}
	}
}

func setup(t *testing.T) *testutil.System {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Error creating kernel: %v", err)
	}

	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)

	k.VFS().MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList:  true,
		AllowUserMount: true,
	})

	mntns, err := k.VFS().NewMountNamespace(ctx, creds, "", tmpfs.Name, &vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("NewMountNamespace(): %v", err)
	}

	return testutil.NewSystem(ctx, t, k.VFS(), mntns)
}

// newTestConnection creates a fuse connection that the sentry can communicate with
// and the FD for the server to communicate with.
func newTestConnection(system *testutil.System, k *kernel.Kernel, maxInFlightRequests uint64) (*Connection, *vfs.FileDescription, error) {
	vfsObj := &vfs.VirtualFilesystem{}
	fuseDev := &DeviceFD{}

	if err := vfsObj.Init(); err != nil {
		return nil, nil, err
	}

	vd := vfsObj.NewAnonVirtualDentry("genCountFD")
	defer vd.DecRef()
	if err := fuseDev.vfsfd.Init(fuseDev, linux.O_RDWR|linux.O_CREAT, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, nil, err
	}

	fsopts := filesystemOptions{
		maxInflightRequests: maxInFlightRequests,
	}
	fs, err := NewFUSEFilesystem(system.Ctx, 0, &fsopts, &fuseDev.vfsfd)
	if err != nil {
		return nil, nil, err
	}

	return fs.conn, &fuseDev.vfsfd, nil
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *testPayload) SizeBytes() int {
	return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *testPayload) MarshalBytes(dst []byte) {
	usermem.ByteOrder.PutUint32(dst[:4], t.data)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *testPayload) UnmarshalBytes(src []byte) {
	*t = testPayload{data: usermem.ByteOrder.Uint32(src[:4])}
}

// Packed implements marshal.Marshallable.Packed.
func (t *testPayload) Packed() bool {
	return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *testPayload) MarshalUnsafe(dst []byte) {
	t.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *testPayload) UnmarshalUnsafe(src []byte) {
	t.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *testPayload) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
	panic("not implemented")
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *testPayload) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
	panic("not implemented")
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *testPayload) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
	panic("not implemented")
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *testPayload) WriteTo(w io.Writer) (int64, error) {
	panic("not implemented")
}
