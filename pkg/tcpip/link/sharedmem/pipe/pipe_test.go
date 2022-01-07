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

package pipe

import (
	"math/rand"
	"reflect"
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
)

func TestSimpleReadWrite(t *testing.T) {
	// Check that a simple write can be properly read from the rx side.
	tr := rand.New(rand.NewSource(99))
	rr := rand.New(rand.NewSource(99))

	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	wb := tx.Push(10)
	if wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	for i := range wb {
		wb[i] = byte(tr.Intn(256))
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	rb := rx.Pull()
	if len(rb) != 10 {
		t.Fatalf("Bad buffer size returned: got %v, want %v", len(rb), 10)
	}

	for i := range rb {
		if v := byte(rr.Intn(256)); v != rb[i] {
			t.Fatalf("Bad read buffer at index %v: got %v, want %v", i, rb[i], v)
		}
	}
	rx.Flush()
}

func TestEmptyRead(t *testing.T) {
	// Check that pulling from an empty pipe fails.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on empty pipe")
	}
}

func TestTooLargeWrite(t *testing.T) {
	// Check that writes that are too large are properly rejected.
	b := make([]byte, 96)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(96); wb != nil {
		t.Fatalf("Write of 96 bytes succeeded on 96-byte pipe")
	}

	if wb := tx.Push(88); wb != nil {
		t.Fatalf("Write of 88 bytes succeeded on 96-byte pipe")
	}

	if wb := tx.Push(80); wb == nil {
		t.Fatalf("Write of 80 bytes failed on 96-byte pipe")
	}
}

func TestFullWrite(t *testing.T) {
	// Check that writes fail when the pipe is full.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(80); wb == nil {
		t.Fatalf("Write of 80 bytes failed on 96-byte pipe")
	}

	if wb := tx.Push(1); wb != nil {
		t.Fatalf("Write succeeded on full pipe")
	}
}

func TestFullAndFlushedWrite(t *testing.T) {
	// Check that writes fail when the pipe is full and has already been
	// flushed.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(80); wb == nil {
		t.Fatalf("Write of 80 bytes failed on 96-byte pipe")
	}

	tx.Flush()

	if wb := tx.Push(1); wb != nil {
		t.Fatalf("Write succeeded on full pipe")
	}
}

func TestTxFlushTwice(t *testing.T) {
	// Checks that a second consecutive tx flush is a no-op.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	// Make copy of original tx queue, flush it, then check that it didn't
	// change.
	orig := tx
	tx.Flush()

	if !reflect.DeepEqual(orig, tx) {
		t.Fatalf("Flush mutated tx pipe: got %v, want %v", tx, orig)
	}
}

func TestRxFlushTwice(t *testing.T) {
	// Checks that a second consecutive rx flush is a no-op.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// Make copy of original rx queue, flush it, then check that it didn't
	// change.
	orig := rx
	rx.Flush()

	if !reflect.DeepEqual(orig, rx) {
		t.Fatalf("Flush mutated rx pipe: got %v, want %v", rx, orig)
	}
}

func TestWrapInMiddleOfTransaction(t *testing.T) {
	// Check that writes are not flushed when we need to wrap the buffer
	// around.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// At this point the ring buffer is empty, but the write is at offset
	// 64 (50 + sizeOfSlotHeader + padding-for-8-byte-alignment).
	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on non-full pipe")
	}

	// We haven't flushed yet, so pull must return nil.
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on non-flushed pipe")
	}

	tx.Flush()

	// The two buffers must be available now.
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}

	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
}

func TestWriteAbort(t *testing.T) {
	// Check that a read fails on a pipe that has had data pushed to it but
	// has aborted the push.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Write failed on empty pipe")
	}

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on empty pipe")
	}

	tx.Abort()
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on empty pipe")
	}
}

func TestWrappedWriteAbort(t *testing.T) {
	// Check that writes are properly aborted even if the writes wrap
	// around.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// At this point the ring buffer is empty, but the write is at offset
	// 64 (50 + sizeOfSlotHeader + padding-for-8-byte-alignment).
	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on non-full pipe")
	}

	// We haven't flushed yet, so pull must return nil.
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on non-flushed pipe")
	}

	tx.Abort()

	// The pushes were aborted, so no data should be readable.
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on non-flushed pipe")
	}

	// Try the same transactions again, but flush this time.
	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on non-full pipe")
	}

	tx.Flush()

	// The two buffers must be available now.
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}

	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
}

func TestEmptyReadOnNonFlushedWrite(t *testing.T) {
	// Check that a read fails on a pipe that has had data pushed to it
	// but not yet flushed.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Write failed on empty pipe")
	}

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on empty pipe")
	}

	tx.Flush()
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull on failed on non-empty pipe")
	}
}

func TestPullAfterPullingEntirePipe(t *testing.T) {
	// Check that Pull fails when the pipe is full, but all of it has
	// already been pulled but not yet flushed.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// At this point the ring buffer is empty, but the write is at offset
	// 64 (50 + sizeOfSlotHeader + padding-for-8-byte-alignment). Write 3
	// buffers that will fill the pipe.
	if wb := tx.Push(10); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}

	if wb := tx.Push(20); wb == nil {
		t.Fatalf("Push failed on non-full pipe")
	}

	if wb := tx.Push(24); wb == nil {
		t.Fatalf("Push failed on non-full pipe")
	}

	tx.Flush()

	// The three buffers must be available now.
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}

	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}

	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}

	// Fourth pull must fail.
	if rb := rx.Pull(); rb != nil {
		t.Fatalf("Pull succeeded on empty pipe")
	}
}

func TestNoRoomToWrapOnPush(t *testing.T) {
	// Check that Push fails when it tries to allocate room to add a wrap
	// message.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	var rx Rx
	rx.Init(b)
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// At this point the ring buffer is empty, but the write is at offset
	// 64 (50 + sizeOfSlotHeader + padding-for-8-byte-alignment). Write 20,
	// which won't fit (64+20+8+padding = 96, which wouldn't leave room for
	// the padding), so it wraps around.
	if wb := tx.Push(20); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}

	tx.Flush()

	// Buffer offset is at 28. Try to write 70, which would require a wrap
	// slot which cannot be created now.
	if wb := tx.Push(70); wb != nil {
		t.Fatalf("Push succeeded on pipe with no room for wrap message")
	}
}

func TestRxImplicitFlushOfWrapMessage(t *testing.T) {
	// Check if the first read is that of a wrapping message, that it gets
	// immediately flushed.
	b := make([]byte, 100)
	var tx Tx
	tx.Init(b)

	if wb := tx.Push(50); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
	tx.Flush()

	// This will cause a wrapping message to written.
	if wb := tx.Push(60); wb != nil {
		t.Fatalf("Push succeeded when there is no room in pipe")
	}

	var rx Rx
	rx.Init(b)

	// Read the first message.
	if rb := rx.Pull(); rb == nil {
		t.Fatalf("Pull failed on non-empty pipe")
	}
	rx.Flush()

	// This should fail because of the wrapping message is taking up space.
	if wb := tx.Push(60); wb != nil {
		t.Fatalf("Push succeeded when there is no room in pipe")
	}

	// Try to read the next one. This should consume the wrapping message.
	rx.Pull()

	// This must now succeed.
	if wb := tx.Push(60); wb == nil {
		t.Fatalf("Push failed on empty pipe")
	}
}

func TestConcurrentReaderWriter(t *testing.T) {
	// Push a million buffers of random sizes and random contents. Check
	// that buffers read match what was written.
	tr := rand.New(rand.NewSource(99))
	rr := rand.New(rand.NewSource(99))

	b := make([]byte, 4096)
	var tx Tx
	tx.Init(b)

	var rx Rx
	rx.Init(b)

	const count = 1000000
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runtime.Gosched()
		for i := 0; i < count; i++ {
			n := 1 + tr.Intn(80)
			wb := tx.Push(uint64(n))
			for wb == nil {
				wb = tx.Push(uint64(n))
			}

			for j := range wb {
				wb[j] = byte(tr.Intn(256))
			}

			tx.Flush()
		}
	}()

	for i := 0; i < count; i++ {
		n := 1 + rr.Intn(80)
		rb := rx.Pull()
		for rb == nil {
			rb = rx.Pull()
		}

		if n != len(rb) {
			t.Fatalf("Bad %v-th buffer length: got %v, want %v", i, len(rb), n)
		}

		for j := range rb {
			if v := byte(rr.Intn(256)); v != rb[j] {
				t.Fatalf("Bad %v-th read buffer at index %v: got %v, want %v", i, j, rb[j], v)
			}
		}

		rx.Flush()
	}
}
