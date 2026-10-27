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

package container

import (
	"slices"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

func TestGoferEnv(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile bool
		environ []string
		want    []string
	}{
		{
			name:    "no GODEBUG",
			environ: []string{"PATH=/bin", "GOMAXPROCS=2"},
			want:    []string{"PATH=/bin", "GODEBUG=memprofilerate=0"},
		},
		{
			name:    "inherited GODEBUG",
			environ: []string{"GODEBUG=gctrace=1", "PATH=/bin"},
			want:    []string{"GODEBUG=memprofilerate=0,gctrace=1", "PATH=/bin"},
		},
		{
			name:    "inherited memprofilerate comes last",
			environ: []string{"GODEBUG=memprofilerate=1"},
			want:    []string{"GODEBUG=memprofilerate=0,memprofilerate=1"},
		},
		{
			name:    "empty GODEBUG",
			environ: []string{"GODEBUG="},
			want:    []string{"GODEBUG=memprofilerate=0"},
		},
		{
			name:    "profile",
			profile: true,
			environ: []string{"GODEBUG=gctrace=1", "GOMAXPROCS=2", "PATH=/bin"},
			want:    []string{"GODEBUG=gctrace=1", "PATH=/bin"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environ := slices.Clone(tc.environ)
			conf := &config.Config{ProfileEnable: tc.profile}
			if got := goferEnv(conf, environ); !slices.Equal(got, tc.want) {
				t.Errorf("goferEnv(%q) = %q, want %q", tc.environ, got, tc.want)
			}
			if !slices.Equal(environ, tc.environ) {
				t.Errorf("goferEnv modified its input: got %q, want %q", environ, tc.environ)
			}
		})
	}
}
