// Copyright 2018 Google LLC
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

package proc

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// meminfoData backs /proc/meminfo.
//
// +stateify savable
type meminfoData struct {
	// k is the owning Kernel.
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*meminfoData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (d *meminfoData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	mf := d.k.MemoryFile()
	mf.UpdateUsage()
	snapshot, totalUsage := usage.MemoryAccounting.Copy()
	totalSize := usage.TotalMemory(mf.TotalSize(), totalUsage)
	anon := snapshot.Anonymous + snapshot.Tmpfs
	file := snapshot.PageCache + snapshot.Mapped
	// We don't actually have active/inactive LRUs, so just make up numbers.
	activeFile := (file / 2) &^ (usermem.PageSize - 1)
	inactiveFile := file - activeFile

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "MemTotal:       %8d kB\n", totalSize/1024)
	memFree := (totalSize - totalUsage) / 1024
	// We use MemFree as MemAvailable because we don't swap.
	// TODO(rahat): When reclaim is implemented the value of MemAvailable
	// should change.
	fmt.Fprintf(&buf, "MemFree:        %8d kB\n", memFree)
	fmt.Fprintf(&buf, "MemAvailable:   %8d kB\n", memFree)
	fmt.Fprintf(&buf, "Buffers:               0 kB\n") // memory usage by block devices
	fmt.Fprintf(&buf, "Cached:         %8d kB\n", (file+snapshot.Tmpfs)/1024)
	// Emulate a system with no swap, which disables inactivation of anon pages.
	fmt.Fprintf(&buf, "SwapCache:             0 kB\n")
	fmt.Fprintf(&buf, "Active:         %8d kB\n", (anon+activeFile)/1024)
	fmt.Fprintf(&buf, "Inactive:       %8d kB\n", inactiveFile/1024)
	fmt.Fprintf(&buf, "Active(anon):   %8d kB\n", anon/1024)
	fmt.Fprintf(&buf, "Inactive(anon):        0 kB\n")
	fmt.Fprintf(&buf, "Active(file):   %8d kB\n", activeFile/1024)
	fmt.Fprintf(&buf, "Inactive(file): %8d kB\n", inactiveFile/1024)
	fmt.Fprintf(&buf, "Unevictable:           0 kB\n") // TODO(b/31823263)
	fmt.Fprintf(&buf, "Mlocked:               0 kB\n") // TODO(b/31823263)
	fmt.Fprintf(&buf, "SwapTotal:             0 kB\n")
	fmt.Fprintf(&buf, "SwapFree:              0 kB\n")
	fmt.Fprintf(&buf, "Dirty:                 0 kB\n")
	fmt.Fprintf(&buf, "Writeback:             0 kB\n")
	fmt.Fprintf(&buf, "AnonPages:      %8d kB\n", anon/1024)
	fmt.Fprintf(&buf, "Mapped:         %8d kB\n", file/1024) // doesn't count mapped tmpfs, which we don't know
	fmt.Fprintf(&buf, "Shmem:          %8d kB\n", snapshot.Tmpfs/1024)
	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*meminfoData)(nil)}}, 0
}
