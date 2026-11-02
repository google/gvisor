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
		name       string
		profile    bool
		environ    []string
		gomaxprocs int
		want       []string
	}{
		{
			name:       "no GODEBUG",
			environ:    []string{"PATH=/bin", "GOMAXPROCS=2"},
			gomaxprocs: 8,
			want: []string{
				"PATH=/bin",
				"GODEBUG=memprofilerate=0,containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=8",
			},
		},
		{
			name:       "inherited GODEBUG",
			environ:    []string{"GODEBUG=gctrace=1", "PATH=/bin"},
			gomaxprocs: 4,
			want: []string{
				"PATH=/bin",
				"GODEBUG=memprofilerate=0,gctrace=1,containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=4",
			},
		},
		{
			name:       "inherited memprofilerate comes before maxprocs",
			environ:    []string{"GODEBUG=memprofilerate=1,containermaxprocs=1", "GODEBUG=ignored=1", "GOMAXPROCS=64"},
			gomaxprocs: 2,
			want: []string{
				"GODEBUG=memprofilerate=0,memprofilerate=1,containermaxprocs=1,containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=2",
			},
		},
		{
			name:       "empty GODEBUG",
			environ:    []string{"GODEBUG="},
			gomaxprocs: 4,
			want: []string{
				"GODEBUG=memprofilerate=0,containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=4",
			},
		},
		{
			name:       "profile",
			profile:    true,
			environ:    []string{"GODEBUG=gctrace=1", "GOMAXPROCS=2", "PATH=/bin"},
			gomaxprocs: 8,
			want: []string{
				"PATH=/bin",
				"GODEBUG=gctrace=1,containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=8",
			},
		},
		{
			name:       "profile with no GODEBUG",
			profile:    true,
			environ:    []string{"PATH=/bin"},
			gomaxprocs: 8,
			want: []string{
				"PATH=/bin",
				"GODEBUG=containermaxprocs=0,updatemaxprocs=0",
				"GOMAXPROCS=8",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environ := slices.Clone(tc.environ)
			conf := &config.Config{ProfileEnable: tc.profile}
			if got := goferEnv(conf, environ, tc.gomaxprocs); !slices.Equal(got, tc.want) {
				t.Errorf("goferEnv(%q, %d) = %q, want %q", tc.environ, tc.gomaxprocs, got, tc.want)
			}
			if !slices.Equal(environ, tc.environ) {
				t.Errorf("goferEnv modified its input: got %q, want %q", environ, tc.environ)
			}
		})
	}
}
