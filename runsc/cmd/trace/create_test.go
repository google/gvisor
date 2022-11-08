// Copyright 2022 The gVisor Authors.
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

package trace

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
)

func TestConfigFile(t *testing.T) {
	testCfg := seccheck.SessionConfig{
		Name: "Default",
		Points: []seccheck.PointConfig{
			{Name: "point-1"},
		},
		Sinks: []seccheck.SinkConfig{{Name: "sink-1"}},
	}

	for _, tc := range []struct {
		name string
		json any
		want seccheck.SessionConfig
		err  string
	}{
		{
			name: "SessionConfig",
			json: testCfg,
			want: testCfg,
		},
		{
			name: "InitConfig",
			json: boot.InitConfig{TraceSession: testCfg},
			want: testCfg,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp, err := os.CreateTemp(testutil.TmpDir(), "trace-create")
			if err != nil {
				t.Fatal(err)
			}
			defer tmp.Close()
			encoder := json.NewEncoder(tmp)
			if err := encoder.Encode(tc.json); err != nil {
				t.Fatal(err)
			}

			config, err := decodeTraceConfig(tmp.Name())
			if len(tc.err) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(&tc.want, config) {
					t.Errorf("loaded trace session is different, want: %+v, got: %+v", &tc.want, config)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("unexpected error, want: %q, got: %v", tc.err, err)
			}
		})
	}
}
