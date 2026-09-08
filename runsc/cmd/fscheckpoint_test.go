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

package cmd

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
)

func TestPathVarSet(t *testing.T) {
	testCases := []struct {
		name      string
		inputs    []string
		want      []checkpoint.ResourceID
		expectErr bool
	}{
		{
			name:   "absolute path",
			inputs: []string{"/tmp"},
			want:   []checkpoint.ResourceID{{Path: "/tmp"}},
		},
		{
			name:   "multiple absolute paths",
			inputs: []string{"/tmp", "/var/log"},
			want: []checkpoint.ResourceID{
				{Path: "/tmp"},
				{Path: "/var/log"},
			},
		},
		{
			name:   "comma separated paths",
			inputs: []string{"/tmp, /var/log"},
			want: []checkpoint.ResourceID{
				{Path: "/tmp"},
				{Path: "/var/log"},
			},
		},
		{
			name:   "container prefixed path",
			inputs: []string{"c1:/tmp"},
			want:   []checkpoint.ResourceID{{ContainerName: "c1", Path: "/tmp"}},
		},
		{
			name:   "all-tmpfs keyword",
			inputs: []string{"all-tmpfs", "c1:all-tmpfs"},
			want: []checkpoint.ResourceID{
				{Path: "all-tmpfs"},
				{ContainerName: "c1", Path: "all-tmpfs"},
			},
		},
		{
			name:      "relative path rejected",
			inputs:    []string{"my/relative/path"},
			expectErr: true,
		},
		{
			name:      "relative path with container rejected",
			inputs:    []string{"c1:my/relative/path"},
			expectErr: true,
		},
		{
			name:      "empty path rejected",
			inputs:    []string{""},
			expectErr: true,
		},
		{
			name:      "whitespace path rejected",
			inputs:    []string{"   "},
			expectErr: true,
		},
		{
			name:      "empty container path rejected",
			inputs:    []string{"c1:"},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var p pathVar
			var err error
			for _, input := range tc.inputs {
				if err = p.Set(input); err != nil {
					break
				}
			}
			if (err != nil) != tc.expectErr {
				t.Fatalf("pathVar.Set(%v) err = %v, expectErr = %v", tc.inputs, err, tc.expectErr)
			}
			if !tc.expectErr && !reflect.DeepEqual([]checkpoint.ResourceID(p), tc.want) {
				t.Errorf("pathVar.Set(%v) = %v, want %v", tc.inputs, p, tc.want)
			}
		})
	}
}

func TestParseRestoreImagePaths(t *testing.T) {
	testCases := []struct {
		name      string
		inputs    []string
		want      []string
		expectErr bool
	}{
		{
			name:   "single path",
			inputs: []string{"/path/to/snap"},
			want:   []string{"/path/to/snap"},
		},
		{
			name:   "two repeated flags",
			inputs: []string{"/path/to/sentry", "/path/to/fs"},
			want:   []string{"/path/to/sentry", "/path/to/fs"},
		},
		{
			name:   "comma separated paths in single flag",
			inputs: []string{"/path/to/sentry, /path/to/fs"},
			want:   []string{"/path/to/sentry", "/path/to/fs"},
		},
		{
			name:      "empty input",
			inputs:    []string{},
			expectErr: true,
		},
		{
			name:      "whitespace only input",
			inputs:    []string{"  ,  "},
			expectErr: true,
		},
		{
			name:      "three paths exceeds hard limit",
			inputs:    []string{"/p1", "/p2", "/p3"},
			expectErr: true,
		},
		{
			name:      "three comma-separated paths exceeds hard limit",
			inputs:    []string{"/p1, /p2, /p3"},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRestoreImagePaths(tc.inputs)
			if (err != nil) != tc.expectErr {
				t.Fatalf("parseRestoreImagePaths(%v) err = %v, expectErr = %v", tc.inputs, err, tc.expectErr)
			}
			if !tc.expectErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseRestoreImagePaths(%v) = %v, want %v", tc.inputs, got, tc.want)
			}
		})
	}
}
