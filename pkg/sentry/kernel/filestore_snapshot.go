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

package kernel

import (
	"fmt"
	"sort"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

// snapshotFilestores reflink-clones every private MemoryFile's backing file
// to its snapshot destination, recording the snapshot's exact size and
// sampled fingerprint both on the MemoryFile (so its ExternalContent save
// embeds snapshot-describing values) and in the returned sidecar entries.
//
// Precondition: the kernel is paused (this runs inside Kernel.SaveTo's
// quiesce window, after mfsToSave has been collected).
func (k *Kernel) snapshotFilestores(mfsToSave map[checkpoint.ResourceID]*pgalloc.MemoryFile, snapshots []checkpoint.FilestoreSnapshot) ([]checkpoint.FilestoreSidecarEntry, error) {
	// Every private MemoryFile must be snapshotted: the checkpoint does not
	// carry its contents, so a missed one would make the checkpoint
	// unrestorable. Fail loudly rather than produce a half-usable artifact.
	targeted := make(map[checkpoint.ResourceID]bool, len(snapshots))
	for _, s := range snapshots {
		targeted[s.ID] = true
	}
	for rid := range mfsToSave {
		if !targeted[rid] {
			return nil, fmt.Errorf("filestore snapshot targets do not cover private memory file %+v (checkpoint would be unrestorable); the caller's mount enumeration is inconsistent with the sandbox's", rid)
		}
	}
	entries := make([]checkpoint.FilestoreSidecarEntry, 0, len(snapshots))
	for _, s := range snapshots {
		mf := mfsToSave[s.ID]
		if mf == nil {
			return nil, fmt.Errorf("filestore snapshot target %+v has no matching private memory file; the caller's mount enumeration is inconsistent with the sandbox's", s.ID)
		}
		size, fp, err := mf.SnapshotToFd(s.Dest)
		if err != nil {
			return nil, fmt.Errorf("snapshotting filestore %+v failed: %w", s.ID, err)
		}
		entries = append(entries, checkpoint.FilestoreSidecarEntry{
			File:              s.Name,
			ResourceContainer: s.ID.ContainerName,
			ResourcePath:      s.ID.Path,
			SizeBytes:         size,
			ChunkCount:        uint64(mf.ChunkCount()),
			Fingerprint:       fp,
		})
	}
	// Deterministic output regardless of caller target order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].File < entries[j].File })
	return entries, nil
}
