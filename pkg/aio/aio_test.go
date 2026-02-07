// Copyright 2024 The gVisor Authors.
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

package aio

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/rand"
)

func testRead(t *testing.T, newQueue func(cap int) (Queue, error)) {
	// Create a temp file.
	testFile, err := os.CreateTemp(t.TempDir(), "aio_test_read")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer testFile.Close()
	defer os.Remove(testFile.Name())

	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data to the file using sync writes.
	if _, err := testFile.Write(data); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Read data from the file using async reads.
	q, err := newQueue(8)
	if err != nil {
		t.Fatalf("failed to create Queue: %v", err)
	}
	defer q.Destroy()
	qavail := q.Cap()
	off := int64(0)
	fd := int32(testFile.Fd())
	buf := make([]byte, dataLen)
	added := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for qavail > 0 && added < dataLen {
			Read(q, 0 /* id */, fd, off, buf[added:added+chunkSize])
			qavail--
			off += chunkSize
			added += chunkSize
		}
		cs, err := q.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("Queue.Wait failed: %v", err)
		}
		for _, c := range cs {
			if err := c.Err(); err != nil {
				t.Fatalf("Queue returned completion with error: %v", err)
			}
			if c.Result != chunkSize {
				t.Fatalf("Queue returned completion of %d bytes, want %d", c.Result, chunkSize)
			}
			qavail++
			done += chunkSize
		}
	}
	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func testReadv(t *testing.T, newQueue func(cap int) (Queue, error)) {
	// Create a temp file.
	testFile, err := os.CreateTemp(t.TempDir(), "aio_test_readv")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer testFile.Close()
	defer os.Remove(testFile.Name())

	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data to the file using sync writes.
	if _, err := testFile.Write(data); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Read data from the file using async vectored reads.
	q, err := newQueue(8)
	if err != nil {
		t.Fatalf("failed to create Queue: %v", err)
	}
	defer q.Destroy()
	qavail := q.Cap()
	iovecsData := make([][2]unix.Iovec, qavail)
	iovecsBusy := bitmap.New(uint32(qavail))
	off := int64(0)
	fd := int32(testFile.Fd())
	buf := make([]byte, dataLen)
	added := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for qavail > 0 && added < dataLen {
			id, err := iovecsBusy.FirstZero(0)
			if err != nil {
				t.Fatalf("all iovecs busy with qavail=%d", qavail)
			}
			iovecsBusy.Add(id)
			iovecs := &iovecsData[id]
			iovecs[0].Base = &buf[added]
			iovecs[0].Len = chunkSize
			iovecs[1].Base = &buf[added+chunkSize]
			iovecs[1].Len = chunkSize
			Readv(q, uint64(id), fd, off, iovecs[:])
			qavail--
			off += 2 * chunkSize
			added += 2 * chunkSize
		}
		cs, err := q.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("Queue.Wait failed: %v", err)
		}
		for _, c := range cs {
			if err := c.Err(); err != nil {
				t.Fatalf("Queue returned completion with error: %v", err)
			}
			if c.Result != 2*chunkSize {
				t.Fatalf("Queue returned completion of %d bytes, want %d", c.Result, 2*chunkSize)
			}
			qavail++
			iovecsBusy.Remove(uint32(c.ID))
			done += 2 * chunkSize
		}
	}
	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func testWrite(t *testing.T, newQueue func(cap int) (Queue, error)) {
	// Create a temp file.
	testFile, err := os.CreateTemp(t.TempDir(), "aio_test_write")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer testFile.Close()
	defer os.Remove(testFile.Name())

	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data to the file using async writes.
	q, err := newQueue(8)
	if err != nil {
		t.Fatalf("failed to create Queue: %v", err)
	}
	defer q.Destroy()
	qavail := q.Cap()
	off := int64(0)
	fd := int32(testFile.Fd())
	added := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for qavail > 0 && added < dataLen {
			Write(q, 0 /* id */, fd, off, data[added:added+chunkSize])
			qavail--
			off += chunkSize
			added += chunkSize
		}
		cs, err := q.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("Queue.Wait failed: %v", err)
		}
		for _, c := range cs {
			if err := c.Err(); err != nil {
				t.Fatalf("Queue returned completion with error: %v", err)
			}
			if c.Result != chunkSize {
				t.Fatalf("Queue returned completion of %d bytes, want %d", c.Result, chunkSize)
			}
			qavail++
			done += chunkSize
		}
	}

	// Read data from the file using sync reads.
	buf := make([]byte, dataLen)
	if n, err := io.ReadFull(testFile, buf); err != nil {
		t.Fatalf("failed to read temp file after %d bytes: %v", n, err)
	}
	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func testWritev(t *testing.T, newQueue func(cap int) (Queue, error)) {
	// Create a temp file.
	testFile, err := os.CreateTemp(t.TempDir(), "aio_test_writev")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer testFile.Close()
	defer os.Remove(testFile.Name())

	// Create random data.
	const chunkSize = 4096
	const dataLen = 1024 * chunkSize
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	// Write data to the file using async vectored writes.
	q, err := newQueue(8)
	if err != nil {
		t.Fatalf("failed to create Queue: %v", err)
	}
	defer q.Destroy()
	qavail := q.Cap()
	iovecsData := make([][2]unix.Iovec, qavail)
	iovecsBusy := bitmap.New(uint32(qavail))
	off := int64(0)
	fd := int32(testFile.Fd())
	added := 0
	done := 0
	var cs []Completion
	for done < dataLen {
		for qavail > 0 && added < dataLen {
			id, err := iovecsBusy.FirstZero(0)
			if err != nil {
				t.Fatalf("all iovecs busy with qavail=%d", qavail)
			}
			iovecsBusy.Add(id)
			iovecs := &iovecsData[id]
			iovecs[0].Base = &data[added]
			iovecs[0].Len = chunkSize
			iovecs[1].Base = &data[added+chunkSize]
			iovecs[1].Len = chunkSize
			Writev(q, uint64(id), fd, off, iovecs[:])
			qavail--
			off += 2 * chunkSize
			added += 2 * chunkSize
		}
		cs, err := q.Wait(cs[:0], 1 /* minCompletions */)
		if err != nil {
			t.Fatalf("Queue.Wait failed: %v", err)
		}
		for _, c := range cs {
			if err := c.Err(); err != nil {
				t.Fatalf("Queue returned completion with error: %v", err)
			}
			if c.Result != 2*chunkSize {
				t.Fatalf("Queue returned completion of %d bytes, want %d", c.Result, 2*chunkSize)
			}
			qavail++
			iovecsBusy.Remove(uint32(c.ID))
			done += 2 * chunkSize
		}
	}

	// Read data from the file using sync reads.
	buf := make([]byte, dataLen)
	if n, err := io.ReadFull(testFile, buf); err != nil {
		t.Fatalf("failed to read temp file after %d bytes: %v", n, err)
	}
	if !bytes.Equal(data, buf) {
		t.Errorf("bytes differ")
	}
}

func testQueue(t *testing.T, newQueue func(cap int) (Queue, error)) {
	t.Run("Read", func(t *testing.T) {
		t.Helper()
		t.Parallel()
		testRead(t, newQueue)
	})
	t.Run("Readv", func(t *testing.T) {
		t.Helper()
		t.Parallel()
		testReadv(t, newQueue)
	})
	t.Run("Write", func(t *testing.T) {
		t.Helper()
		t.Parallel()
		testWrite(t, newQueue)
	})
	t.Run("Writev", func(t *testing.T) {
		t.Helper()
		t.Parallel()
		testWritev(t, newQueue)
	})
}

func TestGoQueue(t *testing.T) {
	testQueue(t, func(cap int) (Queue, error) {
		q := NewGoQueue(cap)
		return q, nil
	})
}
