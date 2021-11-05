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
	"math/rand"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// TestConnectionInitBlock tests if initialization
// correctly blocks and unblocks the connection.
// Since it's unfeasible to test kernelTask.Block() in unit test,
// the code in Call() are not tested here.
func TestConnectionInitBlock(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)

	conn, _, err := newTestConnection(s, k, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	select {
	case <-conn.initializedChan:
		t.Fatalf("initializedChan should be blocking before SetInitialized")
	default:
	}

	conn.SetInitialized()

	select {
	case <-conn.initializedChan:
	default:
		t.Fatalf("initializedChan should not be blocking after SetInitialized")
	}
}

func TestConnectionAbort(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	creds := auth.CredentialsFromContext(s.Ctx)
	task := kernel.TaskFromContext(s.Ctx)

	const numRequests uint64 = 256

	conn, _, err := newTestConnection(s, k, numRequests)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	var futNormal []*futureResponse
	testObj := primitive.Uint32(rand.Uint32())
	for i := 0; i < int(numRequests); i++ {
		req := conn.NewRequest(creds, uint32(i), uint64(i), 0, &testObj)
		fut, err := conn.callFutureLocked(task, req)
		if err != nil {
			t.Fatalf("callFutureLocked failed: %v", err)
		}
		futNormal = append(futNormal, fut)
	}

	conn.Abort(s.Ctx)

	// Abort should unblock the initialization channel.
	// Note: no test requests are actually blocked on `conn.initializedChan`.
	select {
	case <-conn.initializedChan:
	default:
		t.Fatalf("initializedChan should not be blocking after SetInitialized")
	}

	// Abort will return ECONNABORTED error to unblocked requests.
	for _, fut := range futNormal {
		if fut.getResponse().hdr.Error != -int32(unix.ECONNABORTED) {
			t.Fatalf("Incorrect error code received for aborted connection: %v", fut.getResponse().hdr.Error)
		}
	}

	// After abort, Call() should return directly with ENOTCONN.
	req := conn.NewRequest(creds, 0, 0, 0, &testObj)
	_, err = conn.Call(task, req)
	if !linuxerr.Equals(linuxerr.ENOTCONN, err) {
		t.Fatalf("Incorrect error code received for Call() after connection aborted")
	}

}
