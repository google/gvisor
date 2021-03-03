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

package fdchannel

import (
	"io/ioutil"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

func TestSendRecvFD(t *testing.T) {
	sendFile, err := ioutil.TempFile("", "fdchannel_test_")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	defer sendFile.Close()

	chanFDs, err := NewConnectedSockets()
	if err != nil {
		t.Fatalf("failed to create fdchannel sockets: %v", err)
	}
	sendEP := NewEndpoint(chanFDs[0])
	defer sendEP.Destroy()
	recvEP := NewEndpoint(chanFDs[1])
	defer recvEP.Destroy()

	recvFD, err := recvEP.RecvFDNonblock()
	if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
		t.Errorf("RecvFDNonblock before SendFD: got (%d, %v), wanted (<unspecified>, EAGAIN or EWOULDBLOCK", recvFD, err)
	}

	if err := sendEP.SendFD(int(sendFile.Fd())); err != nil {
		t.Fatalf("SendFD failed: %v", err)
	}
	recvFD, err = recvEP.RecvFD()
	if err != nil {
		t.Fatalf("RecvFD failed: %v", err)
	}
	recvFile := os.NewFile(uintptr(recvFD), "received file")
	defer recvFile.Close()

	sendInfo, err := sendFile.Stat()
	if err != nil {
		t.Fatalf("failed to stat sent file: %v", err)
	}
	sendInfoSys := sendInfo.Sys()
	sendStat, ok := sendInfoSys.(*syscall.Stat_t)
	if !ok {
		t.Fatalf("sent file's FileInfo is backed by unknown type %T", sendInfoSys)
	}

	recvInfo, err := recvFile.Stat()
	if err != nil {
		t.Fatalf("failed to stat received file: %v", err)
	}
	recvInfoSys := recvInfo.Sys()
	recvStat, ok := recvInfoSys.(*syscall.Stat_t)
	if !ok {
		t.Fatalf("received file's FileInfo is backed by unknown type %T", recvInfoSys)
	}

	if sendStat.Dev != recvStat.Dev || sendStat.Ino != recvStat.Ino {
		t.Errorf("sent file (dev=%d, ino=%d) does not match received file (dev=%d, ino=%d)", sendStat.Dev, sendStat.Ino, recvStat.Dev, recvStat.Ino)
	}
}

func TestShutdownThenRecvFD(t *testing.T) {
	sendFile, err := ioutil.TempFile("", "fdchannel_test_")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	defer sendFile.Close()

	chanFDs, err := NewConnectedSockets()
	if err != nil {
		t.Fatalf("failed to create fdchannel sockets: %v", err)
	}
	sendEP := NewEndpoint(chanFDs[0])
	defer sendEP.Destroy()
	recvEP := NewEndpoint(chanFDs[1])
	defer recvEP.Destroy()

	recvEP.Shutdown()
	if _, err := recvEP.RecvFD(); err == nil {
		t.Error("RecvFD succeeded unexpectedly")
	}
}

func TestRecvFDThenShutdown(t *testing.T) {
	sendFile, err := ioutil.TempFile("", "fdchannel_test_")
	if err != nil {
		t.Fatalf("failed to create temporary file: %v", err)
	}
	defer sendFile.Close()

	chanFDs, err := NewConnectedSockets()
	if err != nil {
		t.Fatalf("failed to create fdchannel sockets: %v", err)
	}
	sendEP := NewEndpoint(chanFDs[0])
	defer sendEP.Destroy()
	recvEP := NewEndpoint(chanFDs[1])
	defer recvEP.Destroy()

	var receiverWG sync.WaitGroup
	receiverWG.Add(1)
	go func() {
		defer receiverWG.Done()
		if _, err := recvEP.RecvFD(); err == nil {
			t.Error("RecvFD succeeded unexpectedly")
		}
	}()
	defer receiverWG.Wait()
	time.Sleep(time.Second) // to ensure recvEP.RecvFD() has blocked
	recvEP.Shutdown()
}
