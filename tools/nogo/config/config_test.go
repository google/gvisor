// Copyright 2021 The gVisor Authors.
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
// limitations under the License.package nogo

package config

import (
	"go/token"
	"testing"

	"gvisor.dev/gvisor/tools/nogo/check"
)

// TestShouldReport validates the suppression behavior of Config.ShouldReport.
func TestShouldReport(t *testing.T) {
	config := &Config{
		Groups: []Group{
			{
				Name:    "default-enabled",
				Regex:   "^default-enabled/",
				Default: true,
			},
			{
				Name:    "default-disabled",
				Regex:   "^default-disabled/",
				Default: false,
			},
			{
				Name:    "default-disabled-omitted-from-global",
				Regex:   "^default-disabled-omitted-from-global/",
				Default: false,
			},
		},
		Global: AnalyzerConfig{
			"default-enabled": &ItemConfig{
				Exclude:  []string{"excluded.go"},
				Suppress: []string{"suppressed"},
			},
			"default-disabled": &ItemConfig{
				Exclude:  []string{"excluded.go"},
				Suppress: []string{"suppressed"},
			},
			// Omitting default-disabled-omitted-from-global here
			// has no effect on configuration below.
		},
		Analyzers: map[string]AnalyzerConfig{
			"analyzer-suppressions": {
				// Suppress some.
				"default-enabled": &ItemConfig{
					Exclude:  []string{"limited-exclude.go"},
					Suppress: []string{"limited suppress"},
				},
				// Enable all.
				"default-disabled": nil,
			},
			"enabled-for-default-disabled": {
				"default-disabled":                     nil,
				"default-disabled-omitted-from-global": nil,
			},
		},
	}

	if err := config.Compile(); err != nil {
		t.Fatalf("Compile(%+v) = %v, want nil", config, err)
	}

	cases := []struct {
		name    string
		finding check.Finding
		want    bool
	}{
		{
			name: "enabled",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "default-enabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "ungrouped",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "ungrouped/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "suppressed",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "default-enabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message suppressed",
			},
			want: false,
		},
		{
			name: "excluded",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "default-enabled/excluded.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: false,
		},
		{
			name: "disabled",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "default-disabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: false,
		},
		{
			name: "analyzer suppressed",
			finding: check.Finding{
				Category: "analyzer-suppressions",
				Position: token.Position{
					Filename: "default-enabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message limited suppress",
			},
			want: false,
		},
		{
			name: "analyzer suppressed not global",
			finding: check.Finding{
				// Doesn't apply outside of analyzer-suppressions.
				Category: "foo",
				Position: token.Position{
					Filename: "default-enabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message limited suppress",
			},
			want: true,
		},
		{
			name: "analyzer suppressed grouped",
			finding: check.Finding{
				Category: "analyzer-suppressions",
				Position: token.Position{
					// Doesn't apply outside of default-enabled.
					Filename: "default-disabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message limited suppress",
			},
			want: true,
		},
		{
			name: "analyzer excluded",
			finding: check.Finding{
				Category: "analyzer-suppressions",
				Position: token.Position{
					Filename: "default-enabled/limited-exclude.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: false,
		},
		{
			name: "analyzer excluded not global",
			finding: check.Finding{
				// Doesn't apply outside of analyzer-suppressions.
				Category: "foo",
				Position: token.Position{
					Filename: "default-enabled/limited-exclude.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "analyzer excluded grouped",
			finding: check.Finding{
				Category: "analyzer-suppressions",
				Position: token.Position{
					// Doesn't apply outside of default-enabled.
					Filename: "default-disabled/limited-exclude.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "disabled-omitted",
			finding: check.Finding{
				Category: "foo",
				Position: token.Position{
					Filename: "default-disabled-omitted-from-global/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: false,
		},
		{
			name: "default enabled applies to customized analyzer",
			finding: check.Finding{
				Category: "enabled-for-default-disabled",
				Position: token.Position{
					Filename: "default-enabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "default overridden in customized analyzer",
			finding: check.Finding{
				Category: "enabled-for-default-disabled",
				Position: token.Position{
					Filename: "default-disabled/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
		{
			name: "default overridden in customized analyzer even when omitted from global",
			finding: check.Finding{
				Category: "enabled-for-default-disabled",
				Position: token.Position{
					Filename: "default-disabled-omitted-from-global/file.go",
					Offset:   0,
					Line:     1,
					Column:   1,
				},
				Message: "message",
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := config.ShouldReport(tc.finding); got != tc.want {
				t.Errorf("ShouldReport(%+v) = %v, want %v", tc.finding, got, tc.want)
			}
		})
	}
}
