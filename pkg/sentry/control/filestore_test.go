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

package control

import (
	"fmt"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
)

func TestFilestoreSnapshotFilePayload(t *testing.T) {
	for _, pages := range []bool{false, true} {
		for _, split := range []int{0, 1, 2} {
			for _, snapshots := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("pages=%t/split=%d/snapshots=%d", pages, split, snapshots), func(t *testing.T) {
					o := &controlapi.SaveOpts{HavePagesFile: pages}
					addFile := func() int {
						f, err := os.CreateTemp(t.TempDir(), "checkpoint")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { f.Close() })
						o.Files = append(o.Files, f)
						return len(o.Files) - 1
					}
					addFile() // state
					if pages {
						addFile()
						addFile()
					}
					for bundle := 0; bundle < split; bundle++ {
						o.SplitFSCheckpointPaths = append(o.SplitFSCheckpointPaths, fscheckpoint.Bundle{
							Prefix: fmt.Sprintf("bundle%d", bundle),
							Paths:  []checkpoint.ResourceID{{ContainerName: "test", Path: fmt.Sprintf("/mount%d", bundle)}},
						})
						for i := 0; i < 4; i++ {
							addFile()
						}
					}
					for i := 0; i < snapshots; i++ {
						o.FilestoreSnapshot = append(o.FilestoreSnapshot, controlapi.FilestoreSnapshotTarget{
							ResourceID: checkpoint.ResourceID{ContainerName: "test", Path: "/"},
							Name:       "filestore-0",
							FDIndex:    addFile(),
						})
					}
					// -1 is an ordinary checkpoint. Zero still donates the
					// sidecar, exactly as --filestore-snapshot-dir does.
					if snapshots >= 0 {
						o.FilestoreSidecarFDIndex = addFile()
					}
					opts, err := ConvertToStateSaveOpts(o)
					if err != nil {
						t.Fatal(err)
					}
					defer opts.Close()
					wantSnapshots := snapshots
					if wantSnapshots < 0 {
						wantSnapshots = 0
					}
					if got := len(opts.FilestoreSnapshots); got != wantSnapshots {
						t.Errorf("snapshot count = %d, want %d", got, wantSnapshots)
					}
					if (opts.FilestoreSidecar != nil) != (snapshots >= 0) {
						t.Fatalf("sidecar presence does not match request")
					}
					if snapshots >= 0 {
						f := opts.FilestoreSidecar.(*os.File)
						if _, err := f.WriteString("sidecar"); err != nil {
							t.Fatal(err)
						}
						// Verify that the absolute FD index still selects
						// the sidecar after pages and splitFS files.
						data, err := os.ReadFile(o.Files[o.FilestoreSidecarFDIndex].Name())
						if err != nil {
							t.Fatal(err)
						}
						if string(data) != "sidecar" {
							t.Errorf("sidecar contents = %q", data)
						}
					}
					owned := make([]*os.File, 0, len(opts.FilestoreSnapshots)+1)
					for _, snapshot := range opts.FilestoreSnapshots {
						owned = append(owned, snapshot.Dest)
					}
					if opts.FilestoreSidecar != nil {
						owned = append(owned, opts.FilestoreSidecar.(*os.File))
					}
					if err := opts.Close(); err != nil {
						t.Fatal(err)
					}
					for _, file := range owned {
						if _, err := file.Stat(); err == nil {
							t.Errorf("snapshot descriptor %q remains open after Close", file.Name())
						}
					}
				})
			}
		}
	}
}
