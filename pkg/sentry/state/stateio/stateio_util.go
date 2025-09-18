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

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/memutil"
)

// CreateMappedMemoryFD returns a host file descriptor representing a
// memory-backed file of the given size, appropriate for use with
// AsyncReader.RegisterDestinationFD() or AsyncWriter.RegisterSourceFD(), and a
// mapping of that file. The file descriptor should be closed after
// registration (it may be closed while the mapping is still in use). The
// mapping should be released with unix.Munmap() when no longer needed.
func CreateMappedMemoryFD(name string, size int) (int32, []byte, error) {
	fd, err := memutil.CreateMemFD(name, 0 /* flags */)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to create memfd: %w", err)
	}
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("failed to truncate memfd to %d bytes: %w", size, err)
	}
	m, err := unix.Mmap(fd, 0 /* offset */, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("failed to mmap memfd of size %d bytes: %w", size, err)
	}
	return int32(fd), m, nil
}
