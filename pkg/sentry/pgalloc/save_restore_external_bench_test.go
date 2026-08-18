// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"golang.org/x/sys/unix"
)

// benchMemoryFile builds a MemoryFile over a fresh host file and fills sizeMB
// of non-zero pseudo-random-ish data (deterministic pattern), mimicking a
// writable-layer filestore with S MB of dirty contents.
func benchMemoryFile(tb testing.TB, sizeMB int) (*MemoryFile, string) {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, "filestore")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		tb.Fatalf("open: %v", err)
	}
	mf, err := NewMemoryFile(f, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionManual,
		DisableIMAWorkAround:    true,
		DisableMemoryAccounting: true,
		DecommitOnDestroy:       false,
	})
	if err != nil {
		tb.Fatalf("NewMemoryFile: %v", err)
	}
	total := uint64(sizeMB) << 20
	fr, err := mf.Allocate(total, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		tb.Fatalf("Allocate(%d): %v", total, err)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		tb.Fatalf("MapInternal: %v", err)
	}
	// Fill with a cheap deterministic non-zero pattern (no zero-page exclusion
	// advantage for the default save path, matching dirty writable-layer data).
	seed := byte(0x5a)
	for !bs.IsEmpty() {
		s := bs.Head().ToSlice()
		for i := range s {
			s[i] = seed + byte(i%251)
		}
		bs = bs.Tail()
	}
	return mf, path
}

// BenchmarkSaveToDefault measures the native save path: zero-page scanning +
// page serialization into the image.
func BenchmarkSaveToDefault(b *testing.B) {
	benchSaveTo(b, false)
}

// BenchmarkSaveToExternalContent measures the adopt-filestore save path:
// segment metadata only, no scanning, no page serialization.
func BenchmarkSaveToExternalContent(b *testing.B) {
	benchSaveTo(b, true)
}

func benchSaveTo(b *testing.B, external bool) {
	for _, sizeMB := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("%dMB", sizeMB), func(b *testing.B) {
			mf, _ := benchMemoryFile(b, sizeMB)
			defer mf.Destroy()
			var out bytes.Buffer
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out.Reset()
				opts := &SaveOpts{ExternalContent: external}
				if err := mf.SaveTo(context.Background(), &out, opts); err != nil {
					b.Fatalf("SaveTo: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(out.Len())/float64(sizeMB<<20), "image_bytes_per_data_MB")
		})
	}
}

// BenchmarkLoadFromDefault measures the native restore path: read all page
// contents from the image back into the MemoryFile.
func BenchmarkLoadFromDefault(b *testing.B) {
	for _, sizeMB := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("%dMB", sizeMB), func(b *testing.B) {
			orig, path := benchMemoryFile(b, sizeMB)
			var img bytes.Buffer
			if err := orig.SaveTo(context.Background(), &img, &SaveOpts{}); err != nil {
				b.Fatalf("SaveTo: %v", err)
			}
			image := append([]byte(nil), img.Bytes()...)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mf, _ := adoptFileForBench(b, path, false)
				if err := mf.LoadFrom(context.Background(), bytes.NewReader(image), &LoadOpts{}); err != nil {
					b.Fatalf("LoadFrom: %v", err)
				}
				mf.Destroy()
			}
		})
	}
}

// BenchmarkLoadFromAdopted measures the adopt-filestore restore path: load
// segment metadata over an adopted host file; no page I/O at all.
func BenchmarkLoadFromAdopted(b *testing.B) {
	for _, sizeMB := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("%dMB", sizeMB), func(b *testing.B) {
			orig, path := benchMemoryFile(b, sizeMB)
			var img bytes.Buffer
			if err := orig.SaveTo(context.Background(), &img, &SaveOpts{ExternalContent: true}); err != nil {
				b.Fatalf("SaveTo(ExternalContent): %v", err)
			}
			image := append([]byte(nil), img.Bytes()...)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mf, _ := adoptFileForBench(b, path, true)
				if err := mf.LoadFrom(context.Background(), bytes.NewReader(image), &LoadOpts{}); err != nil {
					b.Fatalf("LoadFrom(adopt): %v", err)
				}
				mf.Destroy()
			}
		})
	}
}

// BenchmarkFilestoreSnapshot measures the out-of-band host file snapshot that
// the adopt-filestore design requires on park. The filestore host file is
// chunk-granular (1 GiB sparse), so three variants matter:
//   - FullCopy: naive io.Copy of the whole file (copies holes as zeros);
//   - SparseCopy: extent copy via SEEK_DATA/SEEK_HOLE (like cp --sparse=always);
//   - Ficlone: ioctl(FICLONE) reflink (O(metadata) on supporting filesystems).
func BenchmarkFilestoreSnapshot(b *testing.B) {
	for _, sizeMB := range []int{8, 64, 256} {
		for _, variant := range []string{"FullCopy", "SparseCopy", "Ficlone"} {
			b.Run(fmt.Sprintf("%dMB/%s", sizeMB, variant), func(b *testing.B) {
				_, path := benchMemoryFile(b, sizeMB)
				fi, err := os.Stat(path)
				if err != nil {
					b.Fatalf("stat: %v", err)
				}
				b.ReportMetric(float64(fi.Size()>>20), "file_apparent_MB")
				snap := filepath.Join(b.TempDir(), "snapshot")
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := snapshotFile(path, snap, variant); err != nil {
						b.Fatalf("snapshot(%s): %v", variant, err)
					}
					os.Remove(snap)
				}
			})
		}
	}
}

func snapshotFile(src, dst, variant string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	switch variant {
	case "FullCopy":
		_, err = io.Copy(out, in)
		return err
	case "SparseCopy":
		// Extent copy: for each data extent [data, hole), seek dst to the
		// same offset and copy the extent, leaving holes as holes.
		off := int64(0)
		fi, err := in.Stat()
		if err != nil {
			return err
		}
		size := fi.Size()
		for off < size {
			data, err := unix.Seek(int(in.Fd()), off, unix.SEEK_DATA)
			if err != nil {
				// Only holes remain.
				break
			}
			if data >= size {
				break
			}
			hole, err := unix.Seek(int(in.Fd()), data, unix.SEEK_HOLE)
			if err != nil || hole > size {
				hole = size
			}
			if _, err := out.Seek(data, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.CopyN(out, io.NewSectionReader(in, data, hole-data), hole-data); err != nil {
				return err
			}
			off = hole
		}
		return out.Truncate(size)
	case "Ficlone":
		return unix.IoctlFileClone(int(out.Fd()), int(in.Fd()))
	default:
		return fmt.Errorf("unknown variant %q", variant)
	}
}

func adoptFileForBench(tb testing.TB, path string, adopt bool) (*MemoryFile, string) {
	tb.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		tb.Fatalf("open: %v", err)
	}
	mf, err := NewMemoryFile(f, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionManual,
		DisableIMAWorkAround:    true,
		DisableMemoryAccounting: true,
		DecommitOnDestroy:       false,
		AdoptExistingFile:       adopt,
	})
	if err != nil {
		tb.Fatalf("NewMemoryFile(adopt=%v): %v", adopt, err)
	}
	return mf, path
}
