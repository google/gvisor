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
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/zip"
)

// Verbatim notices from the modules that exposed incomplete discovery:
// https://github.com/JohnCGriffin/overflow/blob/46fa312c3/README.md
// https://github.com/aymanbagabas/go-udiff/tree/4608934d2
var (
	//go:embed testdata/overflow-readme.txt
	overflowReadme string
	//go:embed testdata/udiff-bsd.txt
	udiffBSD string
	//go:embed testdata/udiff-mit.txt
	udiffMIT string
)

func TestFetchPreservesManualArtifact(t *testing.T) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("release artifact")))
	for _, audit := range []struct {
		name     string
		licenses Licenses
		manual   bool
	}{
		{"local reference", Licenses{"LicenseRef-CodeQL", "MIT"}, false},
		{"standard terms", Licenses{"Apache-2.0", "BSD-3-Clause"}, true},
	} {
		t.Run(audit.name, func(t *testing.T) {
			p := Paths{YAML: filepath.Join(t.TempDir(), "dependencies.yaml")}
			original := Entry{
				Dependency: "bundle", Version: "https://example.com/bundle-v1.tar.gz",
				Retrieved: "2026-10-02", SHA256: hash,
				License: audit.licenses, ManuallyAudited: audit.manual,
			}
			automatic := original
			automatic.Dependency = "automatic"
			automatic.License = Licenses{"BSD-3-Clause"}
			automatic.ManuallyAudited = false
			if err := writeEntries(p.YAML, []Entry{original, automatic}); err != nil {
				t.Fatal(err)
			}
			deps := []dep{
				{name: original.Dependency, kind: kindArchive, url: original.Version, sha256: hash},
				{name: automatic.Dependency, kind: kindArchive, url: automatic.Version, sha256: hash},
			}
			// Successful discovery of the repository's MIT notice must not
			// overwrite the artifact's complete manually audited terms.
			retrieve := func(d dep) (*fetched, error) {
				licenses, err := classify(udiffMIT)
				return &fetched{sha256: d.sha256, license: licenses}, err
			}
			if err := fetch(p, deps, retrieve); err != nil {
				t.Fatal(err)
			}
			entries, err := readEntries(p.YAML)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := len(entries), 2; got != want {
				t.Fatalf("catalog has %d entries, want %d", got, want)
			}
			if got, want := entries[0], original; !reflect.DeepEqual(got, want) {
				t.Errorf("manual entry = %+v, want unchanged %+v", got, want)
			}
			if got, want := entries[1].License, (Licenses{"MIT"}); !slices.Equal(got, want) {
				t.Errorf("automatic licenses = %v, want %v", got, want)
			}
			// Recognizing or retaining terms does not approve their use.
			policy := &Policy{AllowedLicenses: []License{"MIT"}}
			want := []string{fmt.Sprintf("bundle uses disallowed licenses %v and has no exception in the policy", original.License)}
			if got := CheckPolicy(entries, policy); !slices.Equal(got, want) {
				t.Errorf("CheckPolicy = %v, want %v", got, want)
			}
			policy.Exceptions = []Exception{{Dependency: "bundle", License: original.License, ExceptionRationale: "reviewed artifact terms"}}
			if got, want := CheckPolicy(entries, policy), []string(nil); !slices.Equal(got, want) {
				t.Errorf("CheckPolicy with scoped exception = %v, want %v", got, want)
			}
		})
	}
}

func TestFetchRejectsInvalidManualAudit(t *testing.T) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("release artifact v1")))
	changedHash := fmt.Sprintf("%x", sha256.Sum256([]byte("release artifact v2")))
	const url = "https://example.com/bundle-v1.tar.gz"
	for _, test := range []struct {
		name, url, hash string
		licenses        Licenses
		manual          bool
		duplicate       bool
		wantErr         string
	}{
		{
			name: "changed URL", url: "https://example.com/bundle-v2.tar.gz", hash: hash,
			licenses: Licenses{"LicenseRef-CodeQL"},
			wantErr:  `re-audit the license of bundle: bundle was audited at "` + url + `", but is now "https://example.com/bundle-v2.tar.gz"`,
		},
		{
			name: "changed bytes", url: url, hash: changedHash,
			licenses: Licenses{"LicenseRef-CodeQL"},
			wantErr:  fmt.Sprintf("re-audit the license of bundle: bundle was audited with sha256 %q, but is now pinned to %q", hash, changedHash),
		},
		{
			name: "removed pin", url: url,
			licenses: Licenses{"Apache-2.0", "BSD-3-Clause"}, manual: true,
			wantErr: "re-audit the license of bundle: bundle has manually audited terms without an artifact checksum pin",
		},
		{
			name: "empty local identifier", url: url, hash: hash,
			licenses: Licenses{"LicenseRef-"},
			wantErr:  `re-audit the license of bundle: bundle has unknown license "LicenseRef-"`,
		},
		{
			name: "invalid local identifier", url: url, hash: hash,
			licenses: Licenses{"LicenseRef-Code_QL"},
			wantErr:  `re-audit the license of bundle: bundle has unknown license "LicenseRef-Code_QL"`,
		},
		{
			name: "duplicate entry", url: url, hash: hash,
			licenses:  Licenses{"LicenseRef-CodeQL"},
			duplicate: true,
			wantErr:   "duplicate entry for bundle in %s",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := Paths{YAML: filepath.Join(t.TempDir(), "dependencies.yaml")}
			original := Entry{
				Dependency: "bundle", Version: url, Retrieved: "2026-10-02",
				SHA256: hash, License: test.licenses, ManuallyAudited: test.manual,
			}
			entries := []Entry{original}
			wantErr := test.wantErr
			if test.duplicate {
				entries = append(entries, original)
				wantErr = fmt.Sprintf(wantErr, p.YAML)
			}
			if err := writeEntries(p.YAML, entries); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(p.YAML)
			if err != nil {
				t.Fatal(err)
			}
			deps := []dep{{name: "bundle", kind: kindArchive, url: test.url, sha256: test.hash}}
			err = fetch(p, deps, func(d dep) (*fetched, error) {
				t.Error("retrieved a notice before rejecting the invalid manual audit")
				return nil, fmt.Errorf("unexpected notice retrieval for %s", d.name)
			})
			if err == nil || err.Error() != wantErr {
				t.Fatalf("fetch = %v, want %q", err, wantErr)
			}
			after, err := os.ReadFile(p.YAML)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("fetch rewrote the invalid catalog")
			}
		})
	}
}

func TestModuleLicenses(t *testing.T) {
	const prefix = "example.com/module@v1.0.0/"
	for _, test := range []struct {
		name    string
		files   map[string]string
		want    Licenses
		wantErr string
	}{
		{
			name: "split notices",
			files: map[string]string{
				prefix + "LICENSE-BSD": udiffBSD,
				prefix + "LICENSE-MIT": udiffMIT,
			},
			want: Licenses{"BSD-3-Clause", "MIT"},
		},
		{
			name: "source files alongside notices",
			files: map[string]string{
				prefix + "LICENSE":         udiffMIT,
				prefix + "LICENSE.docs":    udiffBSD,
				prefix + "license.go":      "package licensecheck\n",
				prefix + "license_test.go": "package licensecheck\n",
			},
			want: Licenses{"BSD-3-Clause", "MIT"},
		},
		{
			name: "unrecognized notice alongside known notice",
			files: map[string]string{
				prefix + "LICENSE":     "All rights reserved. Do not redistribute.",
				prefix + "LICENSE-MIT": udiffMIT,
			},
			wantErr: "LICENSE: cannot classify license text",
		},
		{
			name:  "readme grant",
			files: map[string]string{prefix + "README.md": overflowReadme},
			want:  Licenses{"MIT"},
		},
		{
			name: "primary notices take precedence",
			files: map[string]string{
				prefix + "License_BSD": udiffBSD,
				prefix + "README.md":   overflowReadme,
			},
			want: Licenses{"BSD-3-Clause"},
		},
		{
			name: "unrecognized primary notice",
			files: map[string]string{
				prefix + "COPYING":   "All rights reserved. Do not redistribute.",
				prefix + "README.md": overflowReadme,
			},
			wantErr: "cannot classify license text",
		},
		{
			name:    "readme reference is not a grant",
			files:   map[string]string{prefix + "README": "See https://opensource.org/licenses/MIT for background."},
			wantErr: "cannot classify license text",
		},
		{
			name: "root membership",
			files: map[string]string{
				prefix + "source.go":               udiffMIT,
				prefix + "nested/LICENSE":          udiffMIT,
				"example.com/other@v1.0.0/LICENSE": udiffMIT,
			},
			wantErr: "no license notice at module root",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body bytes.Buffer
			z := zip.NewWriter(&body)
			for name, text := range test.files {
				w, err := z.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write([]byte(text)); err != nil {
					t.Fatal(err)
				}
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := moduleLicenses(body.Bytes(), prefix)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("moduleLicenses = %v, %v, want error %q", got, err, test.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("moduleLicenses = %v, %v, want %v", got, err, test.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	for _, test := range []struct {
		name, text string
		want       Licenses
		wantErr    bool
	}{
		{
			name: "apache",
			text: "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/",
			want: Licenses{apache2},
		},
		{
			name: "apache-llvm",
			text: "Apache License v2.0 with LLVM Exceptions\n\nApache License\nVersion 2.0, January 2004",
			want: Licenses{apache2LLVM},
		},
		{
			name: "mit",
			text: "Permission is hereby granted, free of charge, to any person obtaining a copy of this software",
			want: Licenses{mit},
		},
		{
			name: "bsd3",
			text: "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:\n3. Neither the name of the copyright holder...",
			want: Licenses{bsd3},
		},
		{
			// libbacktrace's license uses a different nonendorsement clause:
			// https://github.com/ianlancetaylor/libbacktrace/blob/793921876/LICENSE
			name: "bsd3 author name",
			text: `# Copyright (C) 2012-2016 Free Software Foundation, Inc.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:

#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.

#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.

#     (3) The name of the author may not be used to
#     endorse or promote products derived from this software without
#     specific prior written permission.`,
			want: Licenses{bsd3},
		},
		{
			name: "bsd2",
			text: "Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1... 2...",
			want: Licenses{bsd2},
		},
		{
			name: "cc0",
			text: "Creative Commons Legal Code\nCC0 1.0 Universal",
			want: Licenses{cc0},
		},
		{
			name: "isc",
			text: "Permission to use, copy, modify, and distribute this software for any purpose with or without fee is hereby granted",
			want: Licenses{isc},
		},
		{
			name: "lgpl21",
			text: "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999",
			want: Licenses{lgpl21},
		},
		{
			name: "dual sorted",
			text: "Permission is hereby granted, free of charge, ...\n...\nApache License\nVersion 2.0",
			want: Licenses{apache2, mit},
		},
		{
			// MPL-2.0 mentions the GNU licenses in its "Secondary License"
			// clause; that must not count as LGPL/GPL.
			name: "mpl mentioning gnu",
			text: "Mozilla Public License Version 2.0\n1.12. \"Secondary License\" means either the GNU General Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero General Public License, Version 3.0, or any later versions of those licenses.",
			want: Licenses{mpl2},
		},
		{
			name:    "unknown",
			text:    "All rights reserved. Do not redistribute.",
			wantErr: true,
		},
	} {
		got, err := classify(test.text)
		if (err != nil) != test.wantErr {
			t.Errorf("%s: err = %v, wantErr = %t", test.name, err, test.wantErr)
			continue
		}
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: classify = %v, want %v", test.name, got, test.want)
		}
		for _, license := range got {
			if !knownLicenses[license] {
				t.Errorf("%s: classify returned unknown license %q", test.name, license)
			}
		}
	}
}

func TestVerifyProblems(t *testing.T) {
	deps := []dep{
		{name: "example.com/mod", kind: kindGoModule, version: "v1.2.0"},
		{name: "some-archive", kind: kindArchive, url: "https://github.com/a/b/archive/refs/tags/v3.tar.gz", sha256: "cafe"},
	}
	entries := []Entry{
		{Dependency: "example.com/mod", Version: "v1.2.0", Retrieved: "2026-08-26", Commit: "abc", SHA256: "beef", License: Licenses{mit}},
		{Dependency: "some-archive", Version: "https://github.com/a/b/archive/refs/tags/v3.tar.gz", Retrieved: "2026-08-26", Commit: "def", SHA256: "cafe", License: Licenses{apache2}},
	}
	if problems := verifyProblems(deps, entries); len(problems) != 0 {
		t.Errorf("verifyProblems on up-to-date entries = %v, want none", problems)
	}
	// A version bump without re-fetching must be flagged, for both kinds.
	deps[0].version = "v1.3.0"
	deps[1].url = "https://github.com/a/b/archive/refs/tags/v4.tar.gz"
	problems := verifyProblems(deps, entries)
	if len(problems) != 2 ||
		!strings.Contains(problems[0], `example.com/mod was audited at "v1.2.0", but is now "v1.3.0"`) ||
		!strings.Contains(problems[1], "some-archive was audited at") {
		t.Errorf("verifyProblems after version bump = %v, want two audited-at problems", problems)
	}
	// A changed archive pin (same URL) must also be flagged.
	deps[0].version = "v1.2.0"
	deps[1].url = "https://github.com/a/b/archive/refs/tags/v3.tar.gz"
	deps[1].sha256 = "d00d"
	problems = verifyProblems(deps, entries)
	if len(problems) != 1 || !strings.Contains(problems[0], `some-archive was audited with sha256 "cafe", but is now pinned to "d00d"`) {
		t.Errorf("verifyProblems after pin change = %v, want one sha256 problem", problems)
	}
	// Missing and stale entries are still flagged.
	deps[0].version = "v1.2.0"
	deps[1].name = "renamed-archive"
	problems = verifyProblems(deps, entries)
	if len(problems) != 2 ||
		!strings.Contains(problems[0], "missing entry for renamed-archive") ||
		!strings.Contains(problems[1], "stale entry for some-archive") {
		t.Errorf("verifyProblems after rename = %v, want missing+stale", problems)
	}
}

// repoRoot finds the directory containing both YAML files: the checkout root
// under `go test`, or the runfiles root under Bazel.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// First check upwards (works for `go test` and Bazel).
	curr := dir
	for range 8 {
		if _, err := os.Stat(filepath.Join(curr, "governance/licensing.yaml")); err == nil {
			return curr
		}
		curr = filepath.Dir(curr)
	}
	// In some test environments, the repo is in a subdirectory of the runfiles root.
	var found string
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if rel, err := filepath.Rel(dir, path); err == nil && strings.Count(rel, string(filepath.Separator)) > 4 {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(filepath.ToSlash(path), "governance/licensing.yaml") {
			candidate := filepath.Dir(filepath.Dir(path))
			if _, err := os.Stat(filepath.Join(candidate, "tools/licensecheck/dependencies.yaml")); err == nil {
				found = candidate
				return fs.SkipAll
			}
		}
		return nil
	})
	if err == nil && found != "" {
		return found
	}
	t.Fatal("cannot find governance/licensing.yaml above or below the working directory")
	return ""
}

// TestLicensePolicy verifies that every dependency in dependencies.yaml
// either uses only licenses in governance/licensing.yaml's allowed_licenses,
// or is on its exceptions list.
func TestLicensePolicy(t *testing.T) {
	root := repoRoot(t)
	entries, err := readEntries(filepath.Join(root, "tools/licensecheck/dependencies.yaml"))
	if err != nil {
		t.Fatalf("cannot read dependencies.yaml: %v", err)
	}
	policy, err := ReadPolicy(filepath.Join(root, "governance/licensing.yaml"))
	if err != nil {
		t.Fatalf("cannot read licensing.yaml: %v", err)
	}
	for _, problem := range CheckPolicy(entries, policy) {
		t.Error(problem)
	}
}

func TestCheckPolicy(t *testing.T) {
	entries := []Entry{
		{Dependency: "a", License: Licenses{mit}},
		{Dependency: "b", License: Licenses{mpl2}},
		{Dependency: "c", License: Licenses{apache2, mpl2}},
		{Dependency: "d", License: Licenses{gpl2}},
	}
	policy := &Policy{
		AllowedLicenses: []License{apache2, mit},
		Exceptions: []Exception{
			{Dependency: "b", License: Licenses{mpl2}, ExceptionRationale: "vendored"},
			{Dependency: "c", License: Licenses{apache2, mpl2}, ExceptionRationale: "notices"},
		},
	}
	if problems := CheckPolicy(entries, policy); len(problems) != 1 || !strings.Contains(problems[0], "d uses disallowed licenses") {
		t.Errorf("CheckPolicy = %v, want a single problem for d", problems)
	}
	// A license mismatch, a stale exception, an unnecessary exception, and
	// the now-uncovered c and d are all flagged.
	policy.Exceptions = []Exception{
		{Dependency: "a", License: Licenses{mit}, ExceptionRationale: "redundant"},
		{Dependency: "b", License: Licenses{unlicense}, ExceptionRationale: "wrong license"},
		{Dependency: "z", License: Licenses{mpl2}, ExceptionRationale: "no longer a dependency"},
	}
	problems := CheckPolicy(entries, policy)
	for _, want := range []string{
		"unnecessary exception for a",
		"exception for b lists licenses Unlicense",
		"exception for z, which is not a dependency",
		"c uses disallowed licenses",
		"d uses disallowed licenses",
	} {
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, want) }) {
			t.Errorf("CheckPolicy = %v, missing problem %q", problems, want)
		}
	}
	if len(problems) != 5 {
		t.Errorf("CheckPolicy returned %d problems, want 5: %v", len(problems), problems)
	}
}
