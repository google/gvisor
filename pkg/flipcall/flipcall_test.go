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
	"testing"
	"time"
)

var testPacketWindowSize = pageSize

func testSendRecv(t *testing.T, ctrlMode ControlMode) {
	pwa, err := NewPacketWindowAllocator()
	if err != nil {
		t.Fatalf("failed to create PacketWindowAllocator: %v", err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(testPacketWindowSize)
	if err != nil {
		t.Fatalf("PacketWindowAllocator.Allocate() failed: %v", err)
	}

	sendEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		t.Fatalf("failed to create Endpoint: %v", err)
	}
	defer sendEP.Destroy()
	recvEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		t.Fatalf("failed to create Endpoint: %v", err)
	}
	defer recvEP.Destroy()

	otherThreadDone := make(chan struct{})
	go func() {
		defer func() { otherThreadDone <- struct{}{} }()
		t.Logf("initially-inactive Endpoint waiting for packet 1")
		if _, err := recvEP.RecvFirst(); err != nil {
			t.Fatalf("initially-inactive Endpoint.RecvFirst() failed: %v", err)
		}
		t.Logf("initially-inactive Endpoint got packet 1, sending packet 2 and waiting for packet 3")
		if _, err := recvEP.SendRecv(0); err != nil {
			t.Fatalf("initially-inactive Endpoint.SendRecv() failed: %v", err)
		}
		t.Logf("initially-inactive Endpoint got packet 3")
	}()
	defer func() {
		t.Logf("waiting for initially-inactive Endpoint goroutine to complete")
		<-otherThreadDone
	}()

	t.Logf("initially-active Endpoint sending packet 1 and waiting for packet 2")
	if _, err := sendEP.SendRecv(0); err != nil {
		t.Fatalf("initially-active Endpoint.SendRecv() failed: %v", err)
	}
	t.Logf("initially-active Endpoint got packet 2, sending packet 3")
	if err := sendEP.SendLast(0); err != nil {
		t.Fatalf("initially-active Endpoint.SendLast() failed: %v", err)
	}
}

func TestFutexSendRecv(t *testing.T) {
	testSendRecv(t, ControlModeFutex)
}

func testRecvFirstShutdown(t *testing.T, ctrlMode ControlMode) {
	pwa, err := NewPacketWindowAllocator()
	if err != nil {
		t.Fatalf("failed to create PacketWindowAllocator: %v", err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(testPacketWindowSize)
	if err != nil {
		t.Fatalf("PacketWindowAllocator.Allocate() failed: %v", err)
	}

	ep, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		t.Fatalf("failed to create Endpoint: %v", err)
	}
	defer ep.Destroy()

	otherThreadDone := make(chan struct{})
	go func() {
		defer func() { otherThreadDone <- struct{}{} }()
		_, err := ep.RecvFirst()
		if err == nil {
			t.Errorf("Endpoint.RecvFirst() succeeded unexpectedly")
		}
	}()

	time.Sleep(time.Second) // to ensure ep.RecvFirst() has blocked
	ep.Shutdown()
	<-otherThreadDone
}

func TestFutexRecvFirstShutdown(t *testing.T) {
	testRecvFirstShutdown(t, ControlModeFutex)
}

func testSendRecvShutdown(t *testing.T, ctrlMode ControlMode) {
	pwa, err := NewPacketWindowAllocator()
	if err != nil {
		t.Fatalf("failed to create PacketWindowAllocator: %v", err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(testPacketWindowSize)
	if err != nil {
		t.Fatalf("PacketWindowAllocator.Allocate() failed: %v", err)
	}

	sendEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		t.Fatalf("failed to create Endpoint: %v", err)
	}
	defer sendEP.Destroy()
	recvEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		t.Fatalf("failed to create Endpoint: %v", err)
	}
	defer recvEP.Destroy()

	otherThreadDone := make(chan struct{})
	go func() {
		defer func() { otherThreadDone <- struct{}{} }()
		if _, err := recvEP.RecvFirst(); err != nil {
			t.Fatalf("initially-inactive Endpoint.RecvFirst() failed: %v", err)
		}
		if _, err := recvEP.SendRecv(0); err == nil {
			t.Errorf("initially-inactive Endpoint.SendRecv() succeeded unexpectedly")
		}
	}()

	if _, err := sendEP.SendRecv(0); err != nil {
		t.Fatalf("initially-active Endpoint.SendRecv() failed: %v", err)
	}
	time.Sleep(time.Second) // to ensure recvEP.SendRecv() has blocked
	recvEP.Shutdown()
	<-otherThreadDone
}

func TestFutexSendRecvShutdown(t *testing.T) {
	testSendRecvShutdown(t, ControlModeFutex)
}

func benchmarkSendRecv(b *testing.B, ctrlMode ControlMode) {
	pwa, err := NewPacketWindowAllocator()
	if err != nil {
		b.Fatalf("failed to create PacketWindowAllocator: %v", err)
	}
	defer pwa.Destroy()
	pwd, err := pwa.Allocate(testPacketWindowSize)
	if err != nil {
		b.Fatalf("PacketWindowAllocator.Allocate() failed: %v", err)
	}

	sendEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		b.Fatalf("failed to create Endpoint: %v", err)
	}
	defer sendEP.Destroy()
	recvEP, err := NewEndpoint(ctrlMode, pwd)
	if err != nil {
		b.Fatalf("failed to create Endpoint: %v", err)
	}
	defer recvEP.Destroy()

	otherThreadDone := make(chan struct{})
	go func() {
		defer func() { otherThreadDone <- struct{}{} }()
		if b.N == 0 {
			return
		}
		if _, err := recvEP.RecvFirst(); err != nil {
			b.Fatalf("initially-inactive Endpoint.RecvFirst() failed: %v", err)
		}
		for i := 1; i < b.N; i++ {
			if _, err := recvEP.SendRecv(0); err != nil {
				b.Fatalf("initially-inactive Endpoint.SendRecv() failed: %v", err)
			}
		}
		if err := recvEP.SendLast(0); err != nil {
			b.Fatalf("initially-inactive Endpoint.SendLast() failed: %v", err)
		}
	}()
	defer func() { <-otherThreadDone }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sendEP.SendRecv(0); err != nil {
			b.Fatalf("initially-active Endpoint.SendRecv() failed: %v", err)
		}
	}
	b.StopTimer()
}

func BenchmarkFutexSendRecv(b *testing.B) {
	benchmarkSendRecv(b, ControlModeFutex)
}
