// Copyright 2018 The gVisor Authors.
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

package queue

import (
	"encoding/binary"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe"
)

func TestBasicTxQueue(t *testing.T) {
	// Tests that a basic transmit on a queue works, and that completion
	// gets properly reported as well.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Tx
	q.Init(pb1, pb2)

	// Enqueue two buffers.
	b := []TxBuffer{
		{nil, 100, 60},
		{nil, 200, 40},
	}

	b[0].Next = &b[1]

	const usedID = 1002
	const usedTotalSize = 100
	if !q.Enqueue(usedID, usedTotalSize, 2, &b[0]) {
		t.Fatalf("Enqueue failed on empty queue")
	}

	// Check the contents of the pipe.
	d := rxp.Pull()
	if d == nil {
		t.Fatalf("Tx pipe is empty after Enqueue")
	}

	want := []byte{
		234, 3, 0, 0, 0, 0, 0, 0, // id
		100, 0, 0, 0, // total size
		0, 0, 0, 0, // reserved
		100, 0, 0, 0, 0, 0, 0, 0, // offset 1
		60, 0, 0, 0, // size 1
		200, 0, 0, 0, 0, 0, 0, 0, // offset 2
		40, 0, 0, 0, // size 2
	}

	if !reflect.DeepEqual(want, d) {
		t.Fatalf("Bad posted packet: got %v, want %v", d, want)
	}

	rxp.Flush()

	// Check that there are no completions yet.
	if _, ok := q.CompletedPacket(); ok {
		t.Fatalf("Packet reported as completed too soon")
	}

	// Post a completion.
	d = txp.Push(8)
	if d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}
	binary.LittleEndian.PutUint64(d, usedID)
	txp.Flush()

	// Check that completion is properly reported.
	id, ok := q.CompletedPacket()
	if !ok {
		t.Fatalf("Completion not reported")
	}

	if id != usedID {
		t.Fatalf("Bad completion id: got %v, want %v", id, usedID)
	}
}

func TestBasicRxQueue(t *testing.T) {
	// Tests that a basic receive on a queue works.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Rx
	q.Init(pb1, pb2, nil)

	// Post two buffers.
	b := []RxBuffer{
		{100, 60, 1077, 0},
		{200, 40, 2123, 0},
	}

	if !q.PostBuffers(b) {
		t.Fatalf("PostBuffers failed on empty queue")
	}

	// Check the contents of the pipe.
	want := [][]byte{
		{
			100, 0, 0, 0, 0, 0, 0, 0, // Offset1
			60, 0, 0, 0, // Size1
			0, 0, 0, 0, // Remaining in group 1
			0, 0, 0, 0, 0, 0, 0, 0, // User data 1
			53, 4, 0, 0, 0, 0, 0, 0, // ID 1
		},
		{
			200, 0, 0, 0, 0, 0, 0, 0, // Offset2
			40, 0, 0, 0, // Size2
			0, 0, 0, 0, // Remaining in group 2
			0, 0, 0, 0, 0, 0, 0, 0, // User data 2
			75, 8, 0, 0, 0, 0, 0, 0, // ID 2
		},
	}

	for i := range b {
		d := rxp.Pull()
		if d == nil {
			t.Fatalf("Tx pipe is empty after PostBuffers")
		}

		if !reflect.DeepEqual(want[i], d) {
			t.Fatalf("Bad posted packet: got %v, want %v", d, want[i])
		}

		rxp.Flush()
	}

	// Check that there are no completions.
	if _, n := q.Dequeue(nil); n != 0 {
		t.Fatalf("Packet reported as received too soon")
	}

	// Post a completion.
	d := txp.Push(sizeOfConsumedPacketHeader + 2*sizeOfConsumedBuffer)
	if d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}

	copy(d, []byte{
		100, 0, 0, 0, // packet size
		0, 0, 0, 0, // reserved

		100, 0, 0, 0, 0, 0, 0, 0, // offset 1
		60, 0, 0, 0, // size 1
		0, 0, 0, 0, 0, 0, 0, 0, // user data 1
		53, 4, 0, 0, 0, 0, 0, 0, // ID 1

		200, 0, 0, 0, 0, 0, 0, 0, // offset 2
		40, 0, 0, 0, // size 2
		0, 0, 0, 0, 0, 0, 0, 0, // user data 2
		75, 8, 0, 0, 0, 0, 0, 0, // ID 2
	})

	txp.Flush()

	// Check that completion is properly reported.
	bufs, n := q.Dequeue(nil)
	if n != 100 {
		t.Fatalf("Bad packet size: got %v, want %v", n, 100)
	}

	if !reflect.DeepEqual(bufs, b) {
		t.Fatalf("Bad returned buffers: got %v, want %v", bufs, b)
	}
}

func TestBadTxCompletion(t *testing.T) {
	// Check that tx completions with bad sizes are properly ignored.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Tx
	q.Init(pb1, pb2)

	// Post a completion that is too short, and check that it is ignored.
	if d := txp.Push(7); d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}
	txp.Flush()

	if _, ok := q.CompletedPacket(); ok {
		t.Fatalf("Bad completion not ignored")
	}

	// Post a completion that is too long, and check that it is ignored.
	if d := txp.Push(10); d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}
	txp.Flush()

	if _, ok := q.CompletedPacket(); ok {
		t.Fatalf("Bad completion not ignored")
	}
}

func TestBadRxCompletion(t *testing.T) {
	// Check that bad rx completions are properly ignored.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Rx
	q.Init(pb1, pb2, nil)

	// Post a completion that is too short, and check that it is ignored.
	if d := txp.Push(7); d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}
	txp.Flush()

	if b, _ := q.Dequeue(nil); b != nil {
		t.Fatalf("Bad completion not ignored")
	}

	// Post a completion whose buffer sizes add up to less than the total
	// size.
	d := txp.Push(sizeOfConsumedPacketHeader + 2*sizeOfConsumedBuffer)
	if d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}

	copy(d, []byte{
		100, 0, 0, 0, // packet size
		0, 0, 0, 0, // reserved

		100, 0, 0, 0, 0, 0, 0, 0, // offset 1
		10, 0, 0, 0, // size 1
		0, 0, 0, 0, 0, 0, 0, 0, // user data 1
		53, 4, 0, 0, 0, 0, 0, 0, // ID 1

		200, 0, 0, 0, 0, 0, 0, 0, // offset 2
		10, 0, 0, 0, // size 2
		0, 0, 0, 0, 0, 0, 0, 0, // user data 2
		75, 8, 0, 0, 0, 0, 0, 0, // ID 2
	})

	txp.Flush()
	if b, _ := q.Dequeue(nil); b != nil {
		t.Fatalf("Bad completion not ignored")
	}

	// Post a completion whose buffer sizes will cause a 32-bit overflow,
	// but adds up to the right number.
	d = txp.Push(sizeOfConsumedPacketHeader + 2*sizeOfConsumedBuffer)
	if d == nil {
		t.Fatalf("Unable to push to rx pipe")
	}

	copy(d, []byte{
		100, 0, 0, 0, // packet size
		0, 0, 0, 0, // reserved

		100, 0, 0, 0, 0, 0, 0, 0, // offset 1
		255, 255, 255, 255, // size 1
		0, 0, 0, 0, 0, 0, 0, 0, // user data 1
		53, 4, 0, 0, 0, 0, 0, 0, // ID 1

		200, 0, 0, 0, 0, 0, 0, 0, // offset 2
		101, 0, 0, 0, // size 2
		0, 0, 0, 0, 0, 0, 0, 0, // user data 2
		75, 8, 0, 0, 0, 0, 0, 0, // ID 2
	})

	txp.Flush()
	if b, _ := q.Dequeue(nil); b != nil {
		t.Fatalf("Bad completion not ignored")
	}
}

func TestFillTxPipe(t *testing.T) {
	// Check that transmitting a new buffer when the buffer pipe is full
	// fails gracefully.
	pb1 := make([]byte, 104)
	pb2 := make([]byte, 104)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Tx
	q.Init(pb1, pb2)

	// Transmit twice, which should fill the tx pipe.
	b := []TxBuffer{
		{nil, 100, 60},
		{nil, 200, 40},
	}

	b[0].Next = &b[1]

	const usedID = 1002
	const usedTotalSize = 100
	for i := uint64(0); i < 2; i++ {
		if !q.Enqueue(usedID+i, usedTotalSize, 2, &b[0]) {
			t.Fatalf("Failed to transmit buffer")
		}
	}

	// Transmit another packet now that the tx pipe is full.
	if q.Enqueue(usedID+2, usedTotalSize, 2, &b[0]) {
		t.Fatalf("Enqueue succeeded when tx pipe is full")
	}
}

func TestFillRxPipe(t *testing.T) {
	// Check that posting a new buffer when the buffer pipe is full fails
	// gracefully.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Rx
	q.Init(pb1, pb2, nil)

	// Post a buffer twice, it should fill the tx pipe.
	b := []RxBuffer{
		{100, 60, 1077, 0},
	}

	for i := 0; i < 2; i++ {
		if !q.PostBuffers(b) {
			t.Fatalf("PostBuffers failed on non-full queue")
		}
	}

	// Post another buffer now that the tx pipe is full.
	if q.PostBuffers(b) {
		t.Fatalf("PostBuffers succeeded on full queue")
	}
}

func TestLotsOfTransmissions(t *testing.T) {
	// Make sure pipes are being properly flushed when transmitting packets.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Tx
	q.Init(pb1, pb2)

	// Prepare packet with two buffers.
	b := []TxBuffer{
		{nil, 100, 60},
		{nil, 200, 40},
	}

	b[0].Next = &b[1]

	const usedID = 1002
	const usedTotalSize = 100

	// Post 100000 packets and completions.
	for i := 100000; i > 0; i-- {
		if !q.Enqueue(usedID, usedTotalSize, 2, &b[0]) {
			t.Fatalf("Enqueue failed on non-full queue")
		}

		if d := rxp.Pull(); d == nil {
			t.Fatalf("Tx pipe is empty after Enqueue")
		}
		rxp.Flush()

		d := txp.Push(8)
		if d == nil {
			t.Fatalf("Unable to write to rx pipe")
		}
		binary.LittleEndian.PutUint64(d, usedID)
		txp.Flush()
		if _, ok := q.CompletedPacket(); !ok {
			t.Fatalf("Completion not returned")
		}
	}
}

func TestLotsOfReceptions(t *testing.T) {
	// Make sure pipes are being properly flushed when receiving packets.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var rxp pipe.Rx
	rxp.Init(pb1)

	var txp pipe.Tx
	txp.Init(pb2)

	var q Rx
	q.Init(pb1, pb2, nil)

	// Prepare for posting two buffers.
	b := []RxBuffer{
		{100, 60, 1077, 0},
		{200, 40, 2123, 0},
	}

	// Post 100000 buffers and completions.
	for i := 100000; i > 0; i-- {
		if !q.PostBuffers(b) {
			t.Fatalf("PostBuffers failed on non-full queue")
		}

		if d := rxp.Pull(); d == nil {
			t.Fatalf("Tx pipe is empty after PostBuffers")
		}
		rxp.Flush()

		if d := rxp.Pull(); d == nil {
			t.Fatalf("Tx pipe is empty after PostBuffers")
		}
		rxp.Flush()

		d := txp.Push(sizeOfConsumedPacketHeader + 2*sizeOfConsumedBuffer)
		if d == nil {
			t.Fatalf("Unable to push to rx pipe")
		}

		copy(d, []byte{
			100, 0, 0, 0, // packet size
			0, 0, 0, 0, // reserved

			100, 0, 0, 0, 0, 0, 0, 0, // offset 1
			60, 0, 0, 0, // size 1
			0, 0, 0, 0, 0, 0, 0, 0, // user data 1
			53, 4, 0, 0, 0, 0, 0, 0, // ID 1

			200, 0, 0, 0, 0, 0, 0, 0, // offset 2
			40, 0, 0, 0, // size 2
			0, 0, 0, 0, 0, 0, 0, 0, // user data 2
			75, 8, 0, 0, 0, 0, 0, 0, // ID 2
		})

		txp.Flush()

		if _, n := q.Dequeue(nil); n == 0 {
			t.Fatalf("Dequeue failed when there is a completion")
		}
	}
}

func TestRxEnableNotification(t *testing.T) {
	// Check that enabling nofifications results in properly updated state.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var state uint32
	var q Rx
	q.Init(pb1, pb2, &state)

	q.EnableNotification()
	if state != eventFDEnabled {
		t.Fatalf("Bad value in shared state: got %v, want %v", state, eventFDEnabled)
	}
}

func TestRxDisableNotification(t *testing.T) {
	// Check that disabling nofifications results in properly updated state.
	pb1 := make([]byte, 100)
	pb2 := make([]byte, 100)

	var state uint32
	var q Rx
	q.Init(pb1, pb2, &state)

	q.DisableNotification()
	if state != eventFDDisabled {
		t.Fatalf("Bad value in shared state: got %v, want %v", state, eventFDDisabled)
	}
}
