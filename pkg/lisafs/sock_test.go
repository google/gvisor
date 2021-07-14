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

package lisafs

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/lisafs/test"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

func runSocketTest(t *testing.T, fun1 func(*sockCommunicator), fun2 func(*sockCommunicator)) {
	sock1, sock2, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer sock1.Close()
	defer sock2.Close()

	var testWg sync.WaitGroup
	testWg.Add(2)

	go func() {
		fun1(newSockComm(sock1))
		testWg.Done()
	}()

	go func() {
		fun2(newSockComm(sock2))
		testWg.Done()
	}()

	testWg.Wait()
}

func TestReadWrite(t *testing.T) {
	// Create random data to send.
	n := 10000
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read(data) failed: %v", err)
	}

	runSocketTest(t, func(comm *sockCommunicator) {
		// Scatter that data into two parts using Iovecs while sending.
		mid := n / 2
		if err := writeTo(comm.sock, [][]byte{data[:mid], data[mid:]}, n, nil); err != nil {
			t.Errorf("writeTo socket failed: %v", err)
		}
	}, func(comm *sockCommunicator) {
		gotData := make([]byte, n)
		if err := readFrom(comm.sock, gotData, nil); err != nil {
			t.Fatalf("reading from socket failed: %v", err)
		}

		// Make sure we got the right data.
		if res := bytes.Compare(data, gotData); res != 0 {
			t.Errorf("data recieved differs from data sent, want = %v, got = %v", data, gotData)
		}
	})
}

func TestFDDonation(t *testing.T) {
	n := 10
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read(data) failed: %v", err)
	}

	// Try donating FDs to these files.
	path1 := "/dev/null"
	path2 := "/dev"
	path3 := "/dev/random"

	runSocketTest(t, func(comm *sockCommunicator) {
		devNullFD, err := unix.Open(path1, unix.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("open(%s) failed: %v", path1, err)
		}
		devFD, err := unix.Open(path2, unix.O_RDONLY, 0)
		if err != nil {
			unix.Close(devNullFD)
			t.Fatalf("open(%s) failed: %v", path2, err)
		}
		devRandomFD, err := unix.Open(path3, unix.O_RDONLY, 0)
		if err != nil {
			unix.Close(devNullFD)
			unix.Close(devFD)
			t.Fatalf("open(%s) failed: %v", path2, err)
		}
		if err := writeTo(comm.sock, [][]byte{data}, n, []int{devNullFD, devFD, devRandomFD}); err != nil {
			t.Errorf("writeTo socket failed: %v", err)
		}
	}, func(comm *sockCommunicator) {
		gotData := make([]byte, n)
		var fds [3]int
		if err := readFrom(comm.sock, gotData, fds[:]); err != nil {
			t.Fatalf("reading from socket failed: %v", err)
		}
		defer closeFDs(fds[:])

		if res := bytes.Compare(data, gotData); res != 0 {
			t.Errorf("data recieved differs from data sent, want = %v, got = %v", data, gotData)
		}

		if len(fds) != 3 {
			t.Fatalf("wanted 3 FD, got %d", len(fds))
		}

		// Check that the FDs actually point to the correct file.
		compareFDWithFile(t, fds[0], path1)
		compareFDWithFile(t, fds[1], path2)
		compareFDWithFile(t, fds[2], path3)
	})
}

func compareFDWithFile(t *testing.T, fd int, path string) {
	var want unix.Stat_t
	if err := unix.Stat(path, &want); err != nil {
		t.Fatalf("stat(%s) failed: %v", path, err)
	}

	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		t.Fatalf("fstat on donated FD failed: %v", err)
	}

	if got.Ino != want.Ino || got.Dev != want.Dev {
		t.Errorf("FD does not point to %s, want = %+v, got = %+v", path, want, got)
	}
}

func TestSndRcvMessage(t *testing.T) {
	req := &test.MsgSimple{}
	req.Randomize()
	reqM := MID(1)

	// Create a massive random response.
	var resp test.MsgDynamic
	resp.Randomize(100)
	respM := MID(2)

	runSocketTest(t, func(comm *sockCommunicator) {
		if err := comm.sndMsg(reqM, req, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
		checkMessageReceive(t, comm, respM, &resp)
	}, func(comm *sockCommunicator) {
		checkMessageReceive(t, comm, reqM, req)
		if err := comm.sndMsg(respM, &resp, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
	})
}

func TestSndRcvMessageNoPayload(t *testing.T) {
	reqM := MID(1)
	respM := MID(2)
	runSocketTest(t, func(comm *sockCommunicator) {
		if err := comm.sndMsg(reqM, nil, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
		checkMessageReceive(t, comm, respM, nil)
	}, func(comm *sockCommunicator) {
		checkMessageReceive(t, comm, reqM, nil)
		if err := comm.sndMsg(respM, nil, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
	})
}

func checkMessageReceive(t *testing.T, comm *sockCommunicator, wantM MID, wantMsg marshal.Marshallable) {
	gotM, gotB, err := comm.rcvMsg(nil)
	if err != nil {
		t.Fatalf("readMessageFrom failed: %v", err)
	}
	if gotM != wantM {
		t.Errorf("got incorrect message ID: got = %d, want = %d", gotM, wantM)
	}
	if wantMsg == nil {
		if len(gotB) != 0 {
			t.Errorf("no payload expect but got %d bytes", len(gotB))
		}
	} else {
		gotMsg := reflect.New(reflect.ValueOf(wantMsg).Elem().Type()).Interface().(marshal.Marshallable)
		gotMsg.UnmarshalBytes(gotB)
		if !reflect.DeepEqual(wantMsg, gotMsg) {
			t.Errorf("msg differs: want = %+v, got = %+v", wantMsg, gotMsg)
		}
	}
}
