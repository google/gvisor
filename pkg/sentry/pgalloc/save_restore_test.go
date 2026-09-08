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

package pgalloc

import (
	"bytes"
	"context"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
)

func TestLoadOptsDiscard(t *testing.T) {
	ctx := context.Background()
	tf, err := os.CreateTemp("", "pgalloc-test")
	if err != nil {
		t.Fatalf("os.CreateTemp failed: %v", err)
	}
	defer os.Remove(tf.Name())

	mf, err := NewMemoryFile(tf, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile failed: %v", err)
	}
	defer mf.Destroy()

	// Allocate 2 pages and populate them with non-zero bytes so they are saved as knownCommitted.
	const allocSize = 2 * hostarch.PageSize
	fr, err := mf.Allocate(allocSize, AllocOpts{Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate failed: %v", err)
	}
	bs, err := mf.MapInternal(fr, hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal failed: %v", err)
	}
	data := make([]byte, allocSize)
	for i := range data {
		data[i] = byte(i%251 + 1) // non-zero
	}
	srcSeq := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(data))
	if n, err := safemem.CopySeq(bs, srcSeq); err != nil || n != uint64(len(data)) {
		t.Fatalf("CopySeq: got (%d, %v), want (%d, nil)", n, err, len(data))
	}

	var buf bytes.Buffer
	if err := mf.SaveTo(ctx, &buf, &SaveOpts{}); err != nil {
		t.Fatalf("SaveTo failed: %v", err)
	}

	savedBytes := buf.Bytes()

	t.Run("InlineDiscard", func(t *testing.T) {
		// Append a sentinel string to ensure the stream is not corrupted and subsequent reads succeed.
		streamBuf := bytes.NewBuffer(append([]byte(nil), savedBytes...))
		const sentinel = "SENTINEL_STREAM_DATA"
		streamBuf.WriteString(sentinel)

		tf2, err := os.CreateTemp("", "pgalloc-test-load")
		if err != nil {
			t.Fatalf("os.CreateTemp failed: %v", err)
		}
		defer os.Remove(tf2.Name())

		mf2, err := NewMemoryFile(tf2, MemoryFileOpts{
			DelayedEviction:         DelayedEvictionDisabled,
			DisableMemoryAccounting: true,
		})
		if err != nil {
			t.Fatalf("NewMemoryFile failed: %v", err)
		}
		defer mf2.Destroy()

		loadOpts := LoadOpts{
			Discard: true,
		}
		if err := mf2.LoadFrom(ctx, streamBuf, &loadOpts); err != nil {
			t.Fatalf("LoadFrom with Discard=true failed: %v", err)
		}

		// Verify the sentinel data immediately follows in the stream.
		remaining := streamBuf.String()
		if remaining != sentinel {
			t.Fatalf("Stream desynchronized: got %q, want %q", remaining, sentinel)
		}

		// Verify mf2 has no memory allocated/committed.
		usage, err := mf2.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage failed: %v", err)
		}
		if usage != 0 {
			t.Fatalf("Expected 0 usage in discarded MemoryFile, got %d", usage)
		}
	})

	t.Run("PagesFileDiscard", func(t *testing.T) {
		// When PagesFile is non-nil, LoadFrom only reads the metadata proto and advances
		// PagesFileOffset by the committed page count without reading page payloads from stream.
		streamBuf := bytes.NewBuffer(append([]byte(nil), savedBytes...))

		tf3, err := os.CreateTemp("", "pgalloc-test-load-pf")
		if err != nil {
			t.Fatalf("os.CreateTemp failed: %v", err)
		}
		defer os.Remove(tf3.Name())

		mf3, err := NewMemoryFile(tf3, MemoryFileOpts{
			DelayedEviction:         DelayedEvictionDisabled,
			DisableMemoryAccounting: true,
		})
		if err != nil {
			t.Fatalf("NewMemoryFile failed: %v", err)
		}
		defer mf3.Destroy()

		initialOffset := uint64(1024)
		loadOpts := LoadOpts{
			Discard:         true,
			PagesFile:       &AsyncPagesFileLoad{},
			PagesFileOffset: initialOffset,
		}
		if err := mf3.LoadFrom(ctx, streamBuf, &loadOpts); err != nil {
			t.Fatalf("LoadFrom with Discard=true and PagesFile failed: %v", err)
		}

		expectedOffset := initialOffset + allocSize
		if loadOpts.PagesFileOffset != expectedOffset {
			t.Fatalf("PagesFileOffset: got %d, want %d", loadOpts.PagesFileOffset, expectedOffset)
		}
	})
}
