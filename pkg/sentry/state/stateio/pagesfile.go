// Copyright 2025 The gVisor Authors.
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

package stateio

const (
	pagesFileFDDefaultMaxReadBytes  = 4 << 20
	pagesFileFDMaxReads             = 12
	pagesFileFDMinReads             = 4
	pagesFileFDDefaultMaxWriteBytes = 256 << 10
	pagesFileFDDefaultMaxWrites     = 128

	// pagesFileMinRangeBytes is the smallest discontiguous range that async
	// page saving and loading use in production: a page, or a 4 KiB block of
	// a MemoryFile saved with subpage saving (pgalloc.SubpageSize4K) on hosts
	// with larger pages.
	pagesFileMinRangeBytes = 4 << 10
)

// pagesFileMaxRanges returns the number of ranges to provision for reads or
// writes of up to maxBytes: one per pagesFileMinRangeBytes, the most that async
// page loading and saving use. With 4 KiB pages, this is one per page. Smaller
// ranges (from test-only subpage sizes) remain correct, since async page
// loading and saving end a read or write when it runs out of ranges.
func pagesFileMaxRanges(maxBytes uint64) int {
	return int(maxBytes / pagesFileMinRangeBytes)
}

// NewPagesFileFDReader returns a FDReader that reads a pages file from the
// given host file descriptor. It takes ownership of the file descriptor.
//
// Preconditions:
// - hostarch.PageSize <= maxReadBytes <= linux.MAX_RW_COUNT.
// - maxParallel > 0.
func NewPagesFileFDReader(fd int32, maxReadBytes uint64, maxParallel int) *FDReader {
	return NewFDReader(fd, maxReadBytes, pagesFileMaxRanges(maxReadBytes), maxParallel)
}

// pagesFileFDReads returns the default number of concurrent reads of a
// pages file by a sandbox that can use the given number of CPUs.
// Concurrent reads into the sandbox's memory contend in the host kernel,
// so going beyond the number of CPUs mostly just wastes CPU time.
// But reads also wait for I/O, so good to have a few of them keep the
// file busy even with fewer CPUs, especially for long-latency filesystem
// (e.g. remote filesystems).
func pagesFileFDReads(cpus int) int {
	return min(pagesFileFDMaxReads, max(pagesFileFDMinReads, cpus))
}

// NewPagesFileFDReaderDefault returns a FDReader that reads a pages file from
// the given host file descriptor, using defaults for MaxReadBytes and
// MaxParallel for a sandbox that can use the given number of CPUs. It takes
// ownership of the file descriptor.
func NewPagesFileFDReaderDefault(fd int32, cpus int) *FDReader {
	return NewPagesFileFDReader(fd, pagesFileFDDefaultMaxReadBytes, pagesFileFDReads(cpus))
}

// NewPagesFileFDWriter returns a FDWriter that writes a pages file to the
// given host file descriptor. It takes ownership of the file descriptor.
//
// Preconditions:
// - hostarch.PageSize <= maxWriteBytes <= linux.MAX_RW_COUNT.
// - maxParallel > 0.
func NewPagesFileFDWriter(fd int32, maxWriteBytes uint64, maxParallel int) *FDWriter {
	return NewFDWriter(fd, maxWriteBytes, pagesFileMaxRanges(maxWriteBytes), maxParallel)
}

// NewPagesFileFDWriterDefault returns a FDWriter that writes to the given host
// file descriptor, using defaults for MaxWriteBytes and MaxParallel. It takes
// ownership of the file descriptor.
func NewPagesFileFDWriterDefault(fd int32) *FDWriter {
	return NewPagesFileFDWriter(fd, pagesFileFDDefaultMaxWriteBytes, pagesFileFDDefaultMaxWrites)
}
