// Copyright 2019 The gVisor Authors.
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

package flipcall

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

var testPacketWindowSize = pageSize

type testConnection struct {
	pwa      PacketWindowAllocator
	clientEP Endpoint
	serverEP Endpoint
}

func newTestConnectionWithOptions(tb testing.TB, clientOpts, serverOpts []EndpointOption) *testConnection {
	c := &testConnection{}
	if err := c.pwa.Init(); err != nil {
		tb.Fatalf("failed to create PacketWindowAllocator: %v", err)
	}
	pwd, err := c.pwa.Allocate(testPacketWindowSize)
	if err != nil {
		c.pwa.Destroy()
		tb.Fatalf("PacketWindowAllocator.Allocate() failed: %v", err)
	}
	if err := c.clientEP.Init(ClientSide, pwd, clientOpts...); err != nil {
		c.pwa.Destroy()
		tb.Fatalf("failed to create client Endpoint: %v", err)
	}
	if err := c.serverEP.Init(ServerSide, pwd, serverOpts...); err != nil {
		c.pwa.Destroy()
		c.clientEP.Destroy()
		tb.Fatalf("failed to create server Endpoint: %v", err)
	}
	return c
}

func newTestConnection(tb testing.TB) *testConnection {
	return newTestConnectionWithOptions(tb, nil, nil)
}

func (c *testConnection) destroy() {
	c.pwa.Destroy()
	c.clientEP.Destroy()
	c.serverEP.Destroy()
}

func testSendRecv(t *testing.T, c *testConnection) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		t.Logf("server Endpoint waiting for packet 1")
		if _, err := c.serverEP.RecvFirst(); err != nil {
			t.Errorf("server Endpoint.RecvFirst() failed: %v", err)
			return
		}
		t.Logf("server Endpoint got packet 1, sending packet 2 and waiting for packet 3")
		if _, err := c.serverEP.SendRecv(0); err != nil {
			t.Errorf("server Endpoint.SendRecv() failed: %v", err)
			return
		}
		t.Logf("server Endpoint got packet 3")
	}()
	defer func() {
		// Ensure that the server goroutine is cleaned up before
		// c.serverEP.Destroy(), even if the test fails.
		c.serverEP.Shutdown()
		serverRun.Wait()
	}()

	t.Logf("client Endpoint establishing connection")
	if err := c.clientEP.Connect(); err != nil {
		t.Fatalf("client Endpoint.Connect() failed: %v", err)
	}
	t.Logf("client Endpoint sending packet 1 and waiting for packet 2")
	if _, err := c.clientEP.SendRecv(0); err != nil {
		t.Fatalf("client Endpoint.SendRecv() failed: %v", err)
	}
	t.Logf("client Endpoint got packet 2, sending packet 3")
	if err := c.clientEP.SendLast(0); err != nil {
		t.Fatalf("client Endpoint.SendLast() failed: %v", err)
	}
	t.Logf("waiting for server goroutine to complete")
	serverRun.Wait()
}

func TestSendRecv(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testSendRecv(t, c)
}

func testShutdownBeforeConnect(t *testing.T, c *testConnection, remoteShutdown bool) {
	if remoteShutdown {
		c.serverEP.Shutdown()
	} else {
		c.clientEP.Shutdown()
	}
	if err := c.clientEP.Connect(); err == nil {
		t.Errorf("client Endpoint.Connect() succeeded unexpectedly")
	}
}

func TestShutdownBeforeConnectLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownBeforeConnect(t, c, false)
}

func TestShutdownBeforeConnectRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownBeforeConnect(t, c, true)
}

func testShutdownDuringConnect(t *testing.T, c *testConnection, remoteShutdown bool) {
	var clientRun sync.WaitGroup
	clientRun.Add(1)
	go func() {
		defer clientRun.Done()
		if err := c.clientEP.Connect(); err == nil {
			t.Errorf("client Endpoint.Connect() succeeded unexpectedly")
		}
	}()
	time.Sleep(time.Second) // to allow c.clientEP.Connect() to block
	if remoteShutdown {
		c.serverEP.Shutdown()
	} else {
		c.clientEP.Shutdown()
	}
	clientRun.Wait()
}

func TestShutdownDuringConnectLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringConnect(t, c, false)
}

func TestShutdownDuringConnectRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringConnect(t, c, true)
}

func testShutdownBeforeRecvFirst(t *testing.T, c *testConnection, remoteShutdown bool) {
	if remoteShutdown {
		c.clientEP.Shutdown()
	} else {
		c.serverEP.Shutdown()
	}
	if _, err := c.serverEP.RecvFirst(); err == nil {
		t.Errorf("server Endpoint.RecvFirst() succeeded unexpectedly")
	}
}

func TestShutdownBeforeRecvFirstLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownBeforeRecvFirst(t, c, false)
}

func TestShutdownBeforeRecvFirstRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownBeforeRecvFirst(t, c, true)
}

func testShutdownDuringRecvFirstBeforeConnect(t *testing.T, c *testConnection, remoteShutdown bool) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		if _, err := c.serverEP.RecvFirst(); err == nil {
			t.Errorf("server Endpoint.RecvFirst() succeeded unexpectedly")
		}
	}()
	time.Sleep(time.Second) // to allow c.serverEP.RecvFirst() to block
	if remoteShutdown {
		c.clientEP.Shutdown()
	} else {
		c.serverEP.Shutdown()
	}
	serverRun.Wait()
}

func TestShutdownDuringRecvFirstBeforeConnectLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringRecvFirstBeforeConnect(t, c, false)
}

func TestShutdownDuringRecvFirstBeforeConnectRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringRecvFirstBeforeConnect(t, c, true)
}

func testShutdownDuringRecvFirstAfterConnect(t *testing.T, c *testConnection, remoteShutdown bool) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		if _, err := c.serverEP.RecvFirst(); err == nil {
			t.Errorf("server Endpoint.RecvFirst() succeeded unexpectedly")
		}
	}()
	defer func() {
		// Ensure that the server goroutine is cleaned up before
		// c.serverEP.Destroy(), even if the test fails.
		c.serverEP.Shutdown()
		serverRun.Wait()
	}()
	if err := c.clientEP.Connect(); err != nil {
		t.Fatalf("client Endpoint.Connect() failed: %v", err)
	}
	if remoteShutdown {
		c.clientEP.Shutdown()
	} else {
		c.serverEP.Shutdown()
	}
	serverRun.Wait()
}

func TestShutdownDuringRecvFirstAfterConnectLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringRecvFirstAfterConnect(t, c, false)
}

func TestShutdownDuringRecvFirstAfterConnectRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringRecvFirstAfterConnect(t, c, true)
}

func testShutdownDuringClientSendRecv(t *testing.T, c *testConnection, remoteShutdown bool) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		if _, err := c.serverEP.RecvFirst(); err != nil {
			t.Errorf("server Endpoint.RecvFirst() failed: %v", err)
		}
		// At this point, the client must be blocked in c.clientEP.SendRecv().
		if remoteShutdown {
			c.serverEP.Shutdown()
		} else {
			c.clientEP.Shutdown()
		}
	}()
	defer func() {
		// Ensure that the server goroutine is cleaned up before
		// c.serverEP.Destroy(), even if the test fails.
		c.serverEP.Shutdown()
		serverRun.Wait()
	}()
	if err := c.clientEP.Connect(); err != nil {
		t.Fatalf("client Endpoint.Connect() failed: %v", err)
	}
	if _, err := c.clientEP.SendRecv(0); err == nil {
		t.Errorf("client Endpoint.SendRecv() succeeded unexpectedly")
	}
}

func TestShutdownDuringClientSendRecvLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringClientSendRecv(t, c, false)
}

func TestShutdownDuringClientSendRecvRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringClientSendRecv(t, c, true)
}

func testShutdownDuringServerSendRecv(t *testing.T, c *testConnection, remoteShutdown bool) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		if _, err := c.serverEP.RecvFirst(); err != nil {
			t.Errorf("server Endpoint.RecvFirst() failed: %v", err)
			return
		}
		if _, err := c.serverEP.SendRecv(0); err == nil {
			t.Errorf("server Endpoint.SendRecv() succeeded unexpectedly")
		}
	}()
	defer func() {
		// Ensure that the server goroutine is cleaned up before
		// c.serverEP.Destroy(), even if the test fails.
		c.serverEP.Shutdown()
		serverRun.Wait()
	}()
	if err := c.clientEP.Connect(); err != nil {
		t.Fatalf("client Endpoint.Connect() failed: %v", err)
	}
	if _, err := c.clientEP.SendRecv(0); err != nil {
		t.Fatalf("client Endpoint.SendRecv() failed: %v", err)
	}
	time.Sleep(time.Second) // to allow serverEP.SendRecv() to block
	if remoteShutdown {
		c.clientEP.Shutdown()
	} else {
		c.serverEP.Shutdown()
	}
	serverRun.Wait()
}

func TestShutdownDuringServerSendRecvLocal(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringServerSendRecv(t, c, false)
}

func TestShutdownDuringServerSendRecvRemote(t *testing.T) {
	c := newTestConnection(t)
	defer c.destroy()
	testShutdownDuringServerSendRecv(t, c, true)
}

func benchmarkSendRecv(b *testing.B, c *testConnection) {
	var serverRun sync.WaitGroup
	serverRun.Add(1)
	go func() {
		defer serverRun.Done()
		if b.N == 0 {
			return
		}
		if _, err := c.serverEP.RecvFirst(); err != nil {
			b.Errorf("server Endpoint.RecvFirst() failed: %v", err)
			return
		}
		for i := 1; i < b.N; i++ {
			if _, err := c.serverEP.SendRecv(0); err != nil {
				b.Errorf("server Endpoint.SendRecv() failed: %v", err)
				return
			}
		}
		if err := c.serverEP.SendLast(0); err != nil {
			b.Errorf("server Endpoint.SendLast() failed: %v", err)
		}
	}()
	defer func() {
		c.serverEP.Shutdown()
		serverRun.Wait()
	}()

	if err := c.clientEP.Connect(); err != nil {
		b.Fatalf("client Endpoint.Connect() failed: %v", err)
	}
	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.clientEP.SendRecv(0); err != nil {
			b.Fatalf("client Endpoint.SendRecv() failed: %v", err)
		}
	}
	b.StopTimer()
}

func BenchmarkSendRecv(b *testing.B) {
	c := newTestConnection(b)
	defer c.destroy()
	benchmarkSendRecv(b, c)
}
