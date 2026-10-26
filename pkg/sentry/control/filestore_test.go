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
	"errors"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
)

func TestFilestoreSnapshotFDLifetime(t *testing.T) {
	for _, pages := range []bool{false, true} {
		t.Run(map[bool]string{false: "inline", true: "pages"}[pages], func(t *testing.T) {
			o := controlapi.SaveOpts{HavePagesFile: pages, NumFilestoreSnapshots: 2}
			n := 3
			if pages {
				n += 2
			}
			for i := 0; i < n; i++ {
				file, err := os.CreateTemp(t.TempDir(), "save-")
				if err != nil {
					t.Fatal(err)
				}
				o.Files = append(o.Files, file)
			}
			defer o.FilePayload.Close()
			opts, err := ConvertToStateSaveOpts(&o)
			if err != nil {
				t.Fatal(err)
			}
			files := append([]*os.File(nil), opts.FilestoreSnapshots...)
			if len(files) != 2 {
				t.Fatalf("got %d snapshots", len(files))
			}
			if err := opts.Close(); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Error("snapshot FD left open")
				}
			}
		})
	}
}

func TestFilestoreSnapshotRejectsInvalidFDCount(t *testing.T) {
	for _, count := range []int{-1, 1, 2} {
		o := controlapi.SaveOpts{NumFilestoreSnapshots: count}
		file, err := os.CreateTemp(t.TempDir(), "state-")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		o.Files = []*os.File{file}
		if opts, err := ConvertToStateSaveOpts(&o); err == nil {
			opts.Close()
			t.Fatalf("accepted count=%d", count)
		}
	}
}
