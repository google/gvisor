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

package boot

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"sync"
	"testing"
	"time"
)

func TestAsyncBufferingReaderAtSequential(t *testing.T) {
	data := make([]byte, 1024*64)
	for i := range data {
		data[i] = byte(i % 251)
	}

	chunkSize := 1024 * 8
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), chunkSize)
	defer abr.Close()

	buf := make([]byte, 1024*4)
	for off := int64(0); off < int64(len(data)); off += int64(len(buf)) {
		n, err := abr.ReadAt(buf, off)
		if err != nil {
			t.Fatalf("ReadAt(off=%d) failed: %v", off, err)
		}
		if n != len(buf) {
			t.Fatalf("ReadAt(off=%d) returned %d bytes, want %d", off, n, len(buf))
		}
		if !bytes.Equal(buf, data[off:off+int64(n)]) {
			t.Fatalf("ReadAt(off=%d) data mismatch", off)
		}
	}
}

func TestAsyncBufferingReaderAtCrossChunk(t *testing.T) {
	data := make([]byte, 1024*32)
	for i := range data {
		data[i] = byte((i * 31) % 256)
	}

	chunkSize := 1024 * 4
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), chunkSize)
	defer abr.Close()

	// Read across chunk boundaries: from chunk 0 into chunk 2.
	off := int64(chunkSize - 100)
	readLen := chunkSize*2 + 200
	buf := make([]byte, readLen)

	n, err := abr.ReadAt(buf, off)
	if err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if n != readLen {
		t.Fatalf("ReadAt returned %d bytes, want %d", n, readLen)
	}
	if !bytes.Equal(buf, data[off:off+int64(readLen)]) {
		t.Fatalf("cross-chunk data mismatch")
	}
}

func TestAsyncBufferingReaderAtOutOfOrderWaiting(t *testing.T) {
	chunkSize := 64
	data := make([]byte, chunkSize*4)
	for i := range data {
		data[i] = byte(i)
	}

	pr, pw := io.Pipe()
	abr := newAsyncBufferingReaderAt(pr, chunkSize)
	defer abr.Close()

	done := make(chan struct{})
	buf := make([]byte, chunkSize)

	// Attempt to read chunk 2 (offset 128..192) before it has been written.
	go func() {
		n, err := abr.ReadAt(buf, int64(chunkSize*2))
		if err != nil {
			t.Errorf("ReadAt failed: %v", err)
		}
		if n != chunkSize {
			t.Errorf("ReadAt returned %d bytes, want %d", n, chunkSize)
		}
		close(done)
	}()

	// Verify the reader is currently blocked waiting for data.
	select {
	case <-done:
		t.Fatalf("ReadAt completed before chunk was written")
	case <-time.After(50 * time.Millisecond):
	}

	// Write chunk 0 and 1.
	if _, err := pw.Write(data[:chunkSize*2]); err != nil {
		t.Fatalf("pw.Write failed: %v", err)
	}

	// Reader should still be blocked.
	select {
	case <-done:
		t.Fatalf("ReadAt completed before chunk 2 was written")
	case <-time.After(50 * time.Millisecond):
	}

	// Write chunk 2 and 3.
	if _, err := pw.Write(data[chunkSize*2:]); err != nil {
		t.Fatalf("pw.Write failed: %v", err)
	}
	pw.Close()

	// Reader should now unblock.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("ReadAt timed out waiting for chunk 2")
	}

	expected := data[chunkSize*2 : chunkSize*3]
	if !bytes.Equal(buf, expected) {
		t.Fatalf("data mismatch: got %v, want %v", buf, expected)
	}
}

func TestAsyncBufferingReaderAtConcurrent(t *testing.T) {
	data := make([]byte, 1024*128)
	for i := range data {
		data[i] = byte(i % 179)
	}

	chunkSize := 1024 * 16
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), chunkSize)
	defer abr.Close()

	var wg sync.WaitGroup
	workers := 8
	readsPerWorker := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for r := 0; r < readsPerWorker; r++ {
				off := int64((workerID*37 + r*101) % (len(data) - 512))
				length := (workerID*17 + r*31) % 4096
				if off+int64(length) > int64(len(data)) {
					length = int(int64(len(data)) - off)
				}
				buf := make([]byte, length)
				n, err := abr.ReadAt(buf, off)
				if err != nil && !errors.Is(err, io.EOF) {
					t.Errorf("worker %d ReadAt(off=%d, len=%d) failed: %v", workerID, off, length, err)
					return
				}
				if !bytes.Equal(buf[:n], data[off:off+int64(n)]) {
					t.Errorf("worker %d ReadAt(off=%d) data mismatch", workerID, off)
					return
				}
			}
		}(w)
	}

	wg.Wait()
}

func TestAsyncBufferingReaderAtEOF(t *testing.T) {
	data := []byte("hello world")
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), 4)
	defer abr.Close()

	// Read beyond EOF.
	buf := make([]byte, 20)
	n, err := abr.ReadAt(buf, 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
	if n != len(data) {
		t.Fatalf("expected %d bytes, got %d", len(data), n)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("unexpected data: %s", string(buf[:n]))
	}

	// Read starting at or past EOF.
	n, err = abr.ReadAt(buf, int64(len(data)))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

func TestAsyncBufferingReaderAtClose(t *testing.T) {
	pr, pw := io.Pipe()
	abr := newAsyncBufferingReaderAt(pr, 64)

	// Close the reader.
	if err := abr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	pw.Close()

	buf := make([]byte, 10)
	_, err := abr.ReadAt(buf, 0)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("expected os.ErrClosed after Close, got: %v", err)
	}

	// Calling Close() multiple times should be safe.
	if err := abr.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestAsyncBufferingReaderAtNegativeOffset(t *testing.T) {
	data := []byte("test data")
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), 64)
	defer abr.Close()

	buf := make([]byte, 4)
	_, err := abr.ReadAt(buf, -1)
	if err == nil {
		t.Fatalf("expected error for negative offset, got nil")
	}
}

func TestAsyncBufferingReaderAtZeroLengthSlice(t *testing.T) {
	data := []byte("test data")
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), 64)
	defer abr.Close()

	n, err := abr.ReadAt(nil, 0)
	if n != 0 || err != nil {
		t.Fatalf("ReadAt(nil, 0) returned (%d, %v), want (0, nil)", n, err)
	}

	n, err = abr.ReadAt([]byte{}, 5)
	if n != 0 || err != nil {
		t.Fatalf("ReadAt([]byte{}, 5) returned (%d, %v), want (0, nil)", n, err)
	}
}

func TestAsyncBufferingReaderAtErrorPropagation(t *testing.T) {
	pr, pw := io.Pipe()
	abr := newAsyncBufferingReaderAt(pr, 64)
	defer abr.Close()

	expectedErr := errors.New("underlying read failed")
	pw.CloseWithError(expectedErr)

	buf := make([]byte, 10)
	_, err := abr.ReadAt(buf, 0)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got: %v", expectedErr, err)
	}
}

func TestAsyncBufferingReaderAtInvalidChunkSize(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on invalid chunkSize <= 0")
		}
	}()
	newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(nil)), 0)
}

func TestAsyncBufferingReaderAtOffsetOverflow(t *testing.T) {
	data := []byte("test")
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), 64)
	defer abr.Close()

	buf := make([]byte, 10)
	_, err := abr.ReadAt(buf, math.MaxInt64-5)
	if err == nil {
		t.Fatalf("expected error on offset overflow, got nil")
	}
}

func TestAsyncBufferingReaderAtNilReader(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil reader")
		}
	}()
	newAsyncBufferingReaderAt(nil, 64)
}

func TestAsyncBufferingReaderAtCloseUnblocksWaitingRead(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	abr := newAsyncBufferingReaderAt(pr, 64)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 100)
		_, err := abr.ReadAt(buf, 0)
		errCh <- err
	}()

	// Give the goroutine time to enter cond.Wait().
	time.Sleep(50 * time.Millisecond)

	if err := abr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("expected os.ErrClosed, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for ReadAt to unblock on Close")
	}
}

type benchMountRange struct {
	start int64
	end   int64
}

func BenchmarkRestoreExtraction(b *testing.B) {
	sizes := []struct {
		name string
		size int64
	}{
		{"4MB", 4 << 20},
		{"16MB", 16 << 20},
		{"64MB", 64 << 20},
		{"128MB", 128 << 20},
		{"256MB", 256 << 20},
	}

	for _, tc := range sizes {
		archiveSize := tc.size
		data := make([]byte, archiveSize)
		for i := range data {
			data[i] = byte(i % 251)
		}

		mountCount := int64(4)
		mountSize := archiveSize / mountCount
		mounts := make([]benchMountRange, mountCount)
		for i := int64(0); i < mountCount; i++ {
			mounts[i] = benchMountRange{
				start: i * mountSize,
				end:   (i + 1) * mountSize,
			}
		}

		b.Run(tc.name, func(b *testing.B) {
			// Baseline: HEAD reading the entire archive into memory via io.ReadAll,
			// then extracting slices via bytes.NewReader.
			b.Run("Head_ReadAll", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(archiveSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					r := io.NopCloser(bytes.NewReader(data))
					allData, err := io.ReadAll(r)
					r.Close()
					if err != nil {
						b.Fatalf("ReadAll failed: %v", err)
					}
					for _, m := range mounts {
						mountReader := bytes.NewReader(allData[m.start:m.end])
						if _, err := io.Copy(io.Discard, mountReader); err != nil {
							b.Fatalf("mount extraction failed: %v", err)
						}
					}
				}
			})

			// Local restore streaming directly from *os.File using SectionReader and
			// a bounded 1 MiB buffer (tmpfsSourceTar).
			b.Run("LocalFile", func(b *testing.B) {
				tmpFile, err := os.CreateTemp(b.TempDir(), "bench-local-tar")
				if err != nil {
					b.Fatalf("failed to create temp file: %v", err)
				}
				defer tmpFile.Close()
				if _, err := tmpFile.Write(data); err != nil {
					b.Fatalf("failed to write data: %v", err)
				}

				b.ReportAllocs()
				b.SetBytes(archiveSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, m := range mounts {
						length := m.end - m.start
						sectionReader := io.NewSectionReader(tmpFile, m.start, length)
						bufSize := int(min(int64(maxTarBufferSize), length))
						mountReader := bufio.NewReaderSize(sectionReader, bufSize)
						if _, err := io.Copy(io.Discard, mountReader); err != nil {
							b.Fatalf("mount extraction failed: %v", err)
						}
					}
				}
			})

			// Local restore with concurrent mount extraction across goroutines.
			b.Run("LocalFileConcurrent", func(b *testing.B) {
				tmpFile, err := os.CreateTemp(b.TempDir(), "bench-local-tar")
				if err != nil {
					b.Fatalf("failed to create temp file: %v", err)
				}
				defer tmpFile.Close()
				if _, err := tmpFile.Write(data); err != nil {
					b.Fatalf("failed to write data: %v", err)
				}

				b.ReportAllocs()
				b.SetBytes(archiveSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var wg sync.WaitGroup
					for _, m := range mounts {
						wg.Add(1)
						go func(m benchMountRange) {
							defer wg.Done()
							length := m.end - m.start
							sectionReader := io.NewSectionReader(tmpFile, m.start, length)
							bufSize := int(min(int64(maxTarBufferSize), length))
							mountReader := bufio.NewReaderSize(sectionReader, bufSize)
							if _, err := io.Copy(io.Discard, mountReader); err != nil {
								b.Errorf("mount extraction failed: %v", err)
							}
						}(m)
					}
					wg.Wait()
				}
			})

			// Remote gofer restore streaming chunks asynchronously with
			// pipelined concurrent mount extraction.
			b.Run("AsyncBufferingConcurrent", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(archiveSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					chunkSize := int(min(8<<20, archiveSize))
					abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), chunkSize)
					var wg sync.WaitGroup
					for _, m := range mounts {
						wg.Add(1)
						go func(m benchMountRange) {
							defer wg.Done()
							length := m.end - m.start
							sectionReader := io.NewSectionReader(abr, m.start, length)
							bufSize := int(min(int64(maxTarBufferSize), length))
							mountReader := bufio.NewReaderSize(sectionReader, bufSize)
							if _, err := io.Copy(io.Discard, mountReader); err != nil {
								b.Errorf("mount extraction failed: %v", err)
							}
						}(m)
					}
					wg.Wait()
					abr.Close()
				}
			})
		})
	}
}

func BenchmarkAsyncBufferingReaderAtReadAt(b *testing.B) {
	const dataSize = 16 << 20 // 16 MiB
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 251)
	}

	chunkSize := 1 << 20 // 1 MiB chunks
	abr := newAsyncBufferingReaderAt(io.NopCloser(bytes.NewReader(data)), chunkSize)
	defer abr.Close()

	// Wait until all data has been buffered.
	buf := make([]byte, 1)
	if _, err := abr.ReadAt(buf, int64(dataSize-1)); err != nil {
		b.Fatalf("failed to read last byte: %v", err)
	}

	readBuf := make([]byte, 64<<10) // 64 KiB read buffer
	b.ReportAllocs()
	b.SetBytes(int64(len(readBuf)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		off := int64((i * 64 * 1024) % (dataSize - len(readBuf)))
		if _, err := abr.ReadAt(readBuf, off); err != nil {
			b.Fatalf("ReadAt failed: %v", err)
		}
	}
}
