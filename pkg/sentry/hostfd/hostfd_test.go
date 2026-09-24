// Copyright 2026 The gVisor Authors.
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

package hostfd

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestIovecsReadWriteInvalidFD(t *testing.T) {
	buf := []byte("hello")
	iovs := []unix.Iovec{
		{
			Base: &buf[0],
			Len:  uint64(len(buf)),
		},
	}
	total, err := iovecsReadWrite(unix.SYS_WRITEV, -1, iovs, -1, 0)
	if err != unix.EBADF {
		t.Errorf("iovecsReadWrite(-1) returned err %v, want EBADF", err)
	}
	if total != 0 {
		t.Errorf("iovecsReadWrite(-1) returned total %d, want 0", total)
	}
}

func TestIovecsReadWriteShortWriteMultiBatch(t *testing.T) {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatalf("Pipe failed: %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	if err := unix.SetNonblock(p[0], true); err != nil {
		t.Fatalf("SetNonblock(read) failed: %v", err)
	}
	if err := unix.SetNonblock(p[1], true); err != nil {
		t.Fatalf("SetNonblock(write) failed: %v", err)
	}

	// Create enough iovecs to span 3 batches. Batch 2 exceeds pipe buffer size
	// to trigger a short write and verify subsequent batches are skipped.
	numIovs := 2*MaxReadWriteIov + 2
	iovs := make([]unix.Iovec, numIovs)

	buf1 := make([]byte, 1)
	buf100 := make([]byte, 100)

	for i := 0; i < MaxReadWriteIov; i++ {
		iovs[i] = unix.Iovec{Base: &buf1[0], Len: 1}
	}
	for i := MaxReadWriteIov; i < 2*MaxReadWriteIov; i++ {
		iovs[i] = unix.Iovec{Base: &buf100[0], Len: 100}
	}
	for i := 2 * MaxReadWriteIov; i < numIovs; i++ {
		iovs[i] = unix.Iovec{Base: &buf1[0], Len: 1}
	}

	total, err := iovecsReadWrite(unix.SYS_WRITEV, int32(p[1]), iovs, -1, 0)
	if err != 0 {
		t.Fatalf("iovecsReadWrite failed: %v", err)
	}

	// Drain pipe and ensure bytes read match returned total.
	drainBuf := make([]byte, 128*1024)
	var drained int
	for {
		n, err := unix.Read(p[0], drainBuf[drained:])
		if n <= 0 || err != nil {
			break
		}
		drained += n
	}

	if drained != int(total) {
		t.Errorf("got %d bytes in pipe, want %d", drained, total)
	}

	batch1Total := MaxReadWriteIov
	batch2Total := MaxReadWriteIov * 100
	if int(total) <= batch1Total || int(total) >= batch1Total+batch2Total {
		t.Errorf("got total %d, want between %d and %d", total, batch1Total, batch1Total+batch2Total)
	}
}
