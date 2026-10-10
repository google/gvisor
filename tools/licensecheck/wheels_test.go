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

package licensecheck

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestPipHubRepositories(t *testing.T) {
	// show_repo prints a Starlark dictionary whose values are JSON strings.
	// Resolve both platform variants using the hub's actual repository map,
	// rather than assuming a particular canonical-name prefix.
	out := `## @build_deps:
hub_repository(
  name = "rules_python++pip+build_deps",
  whl_map = {"example": "{\"wheel_linux\": [], \"wheel_windows\": []}"},
)
`
	repos, err := parseShowRepos(out)
	if err != nil {
		t.Fatal(err)
	}
	hub := repos["@build_deps"]
	for _, test := range []struct {
		name, mapping string
		want          []string
		wantErr       string
	}{
		{"variants", `{"wheel_linux":"resolved+linux","wheel_windows":"resolved+windows"}`, []string{"@@resolved+linux", "@@resolved+windows"}, ""},
		{"shared", `{"wheel_linux":"resolved+shared","wheel_windows":"resolved+shared"}`, []string{"@@resolved+shared"}, ""},
		{"missing", `{"wheel_linux":"resolved+linux"}`, nil, "missing from the hub's repository mapping"},
		{"invalid", `not JSON`, nil, "no JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := hubWheelRefs(hub, test.mapping)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("hubWheelRefs error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("hubWheelRefs = %v, %v, want %v", got, err, test.want)
			}
		})
	}
	if _, err := parseShowRepos(strings.Replace(out, "rules_python++pip", `invalid\q`, 1)); err == nil {
		t.Error("invalid show_repo string escape accepted")
	}
}

func TestWheelDependency(t *testing.T) {
	attrs := map[string][]string{
		"filename": {"example-1.0-py3-none-any.whl"},
		"urls":     {"https://files.pythonhosted.org/example-1.0-py3-none-any.whl"},
		"sha256":   {strings.Repeat("ab", 32)},
	}
	for _, test := range []struct {
		name, attr, value, wantErr string
	}{
		{name: "pinned wheel"},
		{"pip fallback", "filename", "", "explicit wheel filename"},
		{"source archive", "filename", "example-1.0.tar.gz", "explicit wheel filename"},
		{"unhashed", "sha256", "", "SHA256 pin"},
		{"invalid hash", "sha256", strings.Repeat("z", 64), "SHA256 pin"},
		{"credential", "urls", "https://user:secret@example.com/example.whl", "without credentials"},
	} {
		t.Run(test.name, func(t *testing.T) {
			modified := maps.Clone(attrs)
			if test.attr != "" {
				modified[test.attr] = []string{test.value}
			}
			d, err := wheelDependency(repoInfo{rule: "whl_library", attrs: modified})
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("wheelDependency error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || d.name != "pypi/"+attrs["filename"][0] || d.kind != kindWheel || d.url != attrs["urls"][0] || d.sha256 != attrs["sha256"][0] {
				t.Fatalf("wheelDependency = %+v, %v", d, err)
			}
		})
	}
	first := repoInfo{rule: "whl_library", attrs: attrs}
	second := repoInfo{rule: "whl_library", attrs: maps.Clone(attrs)}
	repos := map[string]repoInfo{"@first": first, "@second": second}
	deps, err := enumerateWheels(repos)
	if err != nil || len(deps) != 1 {
		t.Fatalf("shared wheel = %v, %v, want one dependency", deps, err)
	}
	second.attrs["sha256"] = []string{strings.Repeat("cd", 32)}
	if _, err := enumerateWheels(repos); err == nil || !strings.Contains(err.Error(), "conflicting wheel artifacts") {
		t.Fatalf("conflicting wheel error = %v", err)
	}
}

func TestWheelLicenses(t *testing.T) {
	const (
		metadata = "example-1.0.dist-info/METADATA"
		license  = "example-1.0.dist-info/licenses/LICENSE"
		mitText  = "Permission is hereby granted, free of charge, to any person obtaining a copy of this software"
	)
	base := map[string]string{
		metadata: "Metadata-Version: 2.4\nName: example\nVersion: 1.0\nLicense-File: LICENSE\n\n",
		license:  mitText,
	}
	for _, test := range []struct {
		name    string
		change  func(map[string]string)
		want    Licenses
		wantErr string
	}{
		{name: "modern", want: Licenses{mit}},
		{
			name: "legacy",
			change: func(files map[string]string) {
				delete(files, license)
				files["example-1.0.dist-info/LICENSE"] = mitText
			},
			want: Licenses{mit},
		},
		{
			name: "split license",
			change: func(files map[string]string) {
				files[metadata] = strings.Replace(files[metadata], "License-File: LICENSE", "License-File: LICENSE\nLicense-File: LICENSE.APACHE\nLicense-File: LICENSE.BSD", 1)
				files[license] = "See LICENSE.APACHE and LICENSE.BSD."
				files[license+".APACHE"] = "Apache License\nVersion 2.0"
				files[license+".BSD"] = "Redistribution and use in source and binary forms, with or without modification, are permitted"
			},
			want: Licenses{apache2, bsd2},
		},
		{
			name: "vendored copyleft",
			change: func(files map[string]string) {
				files["example/_vendor/other-2.0.dist-info/METADATA"] = "Name: other\nVersion: 2.0\nLicense-File: LICENSE\n\n"
				files["example/_vendor/other-2.0.dist-info/LICENSE"] = "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"
			},
			want: Licenses{lgpl3, mit},
		},
		{
			name:    "missing license",
			change:  func(files map[string]string) { delete(files, license) },
			wantErr: "missing or ambiguous License-File",
		},
		{
			name:    "ambiguous layout",
			change:  func(files map[string]string) { files["example-1.0.dist-info/LICENSE"] = mitText },
			wantErr: "missing or ambiguous License-File",
		},
		{
			name:    "unknown license",
			change:  func(files map[string]string) { files[license] = "All rights reserved." },
			wantErr: "cannot classify license text",
		},
		{
			name: "metadata only",
			change: func(files map[string]string) {
				files[metadata] = "Name: example\nVersion: 1.0\nLicense-Expression: MIT\n\n"
			},
			wantErr: "must declare Name, Version and License-File",
		},
		{
			name: "invalid license path",
			change: func(files map[string]string) {
				files[metadata] = strings.Replace(files[metadata], "License-File: LICENSE", "License-File: ../LICENSE", 1)
			},
			wantErr: "invalid License-File",
		},
		{
			name:    "missing root metadata",
			change:  func(files map[string]string) { delete(files, metadata) },
			wantErr: "top-level METADATA",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := maps.Clone(base)
			if test.change != nil {
				test.change(files)
			}
			body := makeWheel(t, files)
			pin := fmt.Sprintf("%x", sha256.Sum256(body))
			got, err := wheelLicenses(body, pin)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("wheelLicenses error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("wheelLicenses = %v, %v, want %v", got, err, test.want)
			}
		})
	}
	body := makeWheel(t, base)
	if _, err := wheelLicenses(body, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("unverified wheel error = %v", err)
	}
}

func makeWheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
