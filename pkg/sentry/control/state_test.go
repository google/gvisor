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
	"os"
	"path/filepath"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	pkgstate "gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/state/wire"
	"gvisor.dev/gvisor/pkg/urpc"
)

func TestStateSaveGraphEngineOverride(t *testing.T) {
	prevEngine := pkgstate.GraphEngineEnabled()
	defer pkgstate.EnableGraphEngine(prevEngine)

	for _, tc := range []struct {
		name           string
		processDefault bool
		override       bool
	}{
		{
			name:           "override_wire_with_graph",
			processDefault: false,
			override:       true,
		},
		{
			name:           "override_graph_with_wire",
			processDefault: true,
			override:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkgstate.EnableGraphEngine(tc.processDefault)
			defer pkgstate.EnableGraphEngine(prevEngine)

			k, err := testutil.Boot()
			if err != nil {
				t.Fatalf("testutil.Boot() failed: %v", err)
			}
			defer k.Timekeeper().Destroy()
			k.GlobalInit().Release(k.SupervisorContext())
			k.TestOnlySetGlobalInit(nil)
			w := watchdog.New(k, watchdog.Opts{TaskTimeout: time.Minute})
			defer w.Stop()

			statePath := filepath.Join(t.TempDir(), "checkpoint.img")
			outFile, err := os.Create(statePath)
			if err != nil {
				t.Fatalf("os.Create(%s) failed: %v", statePath, err)
			}
			defer outFile.Close()

			override := tc.override
			opts := &controlapi.SaveOpts{
				FilePayload: urpc.FilePayload{
					Files: []*os.File{outFile},
				},
				Metadata:    statefile.CompressionLevelFlateBestSpeed.ToMetadata(),
				Resume:      true,
				GraphEngine: &override,
			}

			s := &State{Kernel: k, Watchdog: w}
			if err := s.Save(opts, &struct{}{}); err != nil {
				t.Fatalf("State.Save() failed: %v", err)
			}

			if got := pkgstate.GraphEngineEnabled(); got != tc.processDefault {
				t.Errorf("GraphEngineEnabled() after Save = %v, want preserved process default %v", got, tc.processDefault)
			}

			inFile, err := os.Open(statePath)
			if err != nil {
				t.Fatalf("os.Open(%s) failed: %v", statePath, err)
			}
			defer inFile.Close()
			rc, _, err := statefile.NewReader(inFile, nil)
			if err != nil {
				t.Fatalf("statefile.NewReader failed: %v", err)
			}
			defer rc.Close()

			hdr, err := pkgstate.ReadHeaderMode(&wire.Reader{Reader: rc})
			if err != nil {
				t.Fatalf("ReadHeaderMode failed: %v", err)
			}
			if !hdr.Object || hdr.Graph != tc.override {
				t.Errorf("saved header = %+v, want Object=true Graph=%v", hdr, tc.override)
			}
		})
	}
}
