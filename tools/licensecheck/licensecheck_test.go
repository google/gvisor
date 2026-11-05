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
	_ "embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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

func TestParseGitHubCodeloadURL(t *testing.T) {
	for _, test := range []struct {
		url  string
		want [3]string
	}{
		{
			url:  "https://codeload.github.com/torvalds/linux/tar.gz/fd73f4a6659897191fa0d40695fe370925dd3780",
			want: [3]string{"torvalds", "linux", "fd73f4a6659897191fa0d40695fe370925dd3780"},
		},
		{
			url:  "https://codeload.github.com/example/project/tar.gz/refs/heads/release/v1",
			want: [3]string{"example", "project", "refs/heads/release/v1"},
		},
		{
			url:  "https://codeload.github.com/example/project/zip/refs/tags/v1.0",
			want: [3]string{"example", "project", "refs/tags/v1.0"},
		},
	} {
		t.Run(test.url, func(t *testing.T) {
			owner, repo, ref, err := parseGitHubURL(test.url)
			if err != nil {
				t.Fatal(err)
			}
			if got := [3]string{owner, repo, ref}; got != test.want {
				t.Errorf("parseGitHubURL = %q, want %q", got, test.want)
			}
		})
	}
}

// The public LLVM source extension imports libraries separately from compiler
// toolchains. Their archive identity comes from the generated repository rule.
func TestLLVMSourceDependency(t *testing.T) {
	const sourceURL = "https://github.com/hermeticbuild/llvm-redist/releases/download/llvmorg-23.1.2-r1/llvm-project-23.1.2.src.tar.zst"
	const sourceSHA = "271da53a2feb0cb221a9276a14268a3b76ad802c7fc8fb1098291a43b06e4c56"
	graph, err := parseModGraph(`{
  "extensionUsages": [
    {"key": "@@llvm+//extensions:llvm.bzl%llvm", "used_repos": ["llvm-project"]},
    {"key": "@@llvm+//extensions:llvm_toolchain.bzl%llvm_toolchain", "used_repos": ["llvm_toolchain"]},
    {"key": "@@another+//extensions:llvm.bzl%llvm", "used_repos": ["unrelated"]}
  ]
}`)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := graph.repoRefs()
	if err != nil {
		t.Fatal(err)
	}
	if want := []repoRef{{"@llvm-project", "llvm-project"}}; !slices.Equal(refs, want) {
		t.Fatalf("source repository selection = %v, want %v", refs, want)
	}
	for _, test := range []struct {
		name, url, sha256, wantErr string
	}{
		{name: "pinned source", url: sourceURL, sha256: sourceSHA},
		{name: "missing URL", sha256: sourceSHA, wantErr: "llvm_project_archive llvm-project has no URL"},
		{name: "missing checksum", url: sourceURL, wantErr: "llvm_project_archive llvm-project has no SHA-256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Missing attributes are omitted, as in show_repo output.
			row := "## @llvm-project:\nllvm_project_archive(\n"
			if test.url != "" {
				row += "  url = \"" + test.url + "\",\n"
			}
			if test.sha256 != "" {
				row += "  sha256 = \"" + test.sha256 + "\",\n"
			}
			repos, err := parseShowRepos(row + ")\n")
			if err != nil {
				t.Fatal(err)
			}
			repo, ok := repos[refs[0].ref]
			if !ok {
				t.Fatalf("show_repo did not report selected repository %s", refs[0].ref)
			}
			got, err := repo.archiveDependency(refs[0].name)
			if test.wantErr != "" {
				if err == nil || err.Error() != test.wantErr {
					t.Fatalf("archiveDependency = %+v, %v, want error %q", got, err, test.wantErr)
				}
				return
			}
			want := dep{name: "llvm-project", kind: kindArchive, url: sourceURL, sha256: sourceSHA}
			if err != nil || got != want {
				t.Fatalf("archiveDependency = %+v, %v, want %+v", got, err, want)
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

// Complete notices copied from the inputs that exposed classifier mistakes:
// bsd.txt and openssl.txt: https://github.com/apache/arrow/blob/e03105efc/go/LICENSE.txt
// llvm.txt: https://github.com/llvm/llvm-project/blob/85ac56026/LICENSE.TXT
var (
	//go:embed testdata/bsd.txt
	bsdText string
	//go:embed testdata/openssl.txt
	opensslText string
	//go:embed testdata/llvm.txt
	llvmText string
)

func TestClassify(t *testing.T) {
	apache, _, ok := strings.Cut(llvmText, "---- LLVM Exceptions to the Apache 2.0 License ----")
	if !ok {
		t.Fatal("LLVM fixture has no exception boundary")
	}
	for _, test := range []struct {
		name, text string
		want       Licenses
	}{
		{"separate grants", opensslText + bsdText + opensslText, Licenses{"BSD-3-Clause", "OpenSSL"}},
		{"llvm", llvmText, Licenses{"Apache-2.0 WITH LLVM-exception", "NCSA"}},
		{"apache without exception", apache, Licenses{"Apache-2.0"}},
		{"unknown", "All rights reserved. Do not redistribute.", nil},
		{"reference", "See https://opensource.org/licenses/MIT for background.", nil},
		{"title", "GNU General Public License Version 2, June 1991", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := classify(test.text)
			if (err != nil) != (test.want == nil) {
				t.Fatalf("classify error = %v, want licenses %v", err, test.want)
			}
			if !slices.Equal(got, test.want) {
				t.Errorf("classify = %v, want %v", got, test.want)
			}
		})
	}
}

func TestVerifyProblems(t *testing.T) {
	deps := []dep{
		{name: "example.com/mod", kind: kindGoModule, version: "v1.2.0"},
		{name: "some-archive", kind: kindArchive, url: "https://github.com/a/b/archive/refs/tags/v3.tar.gz", sha256: "cafe"},
	}
	entries := []Entry{
		{Dependency: "example.com/mod", Version: "v1.2.0", Retrieved: "2026-08-26", Commit: "abc", SHA256: "beef", License: Licenses{"MIT"}},
		{Dependency: "some-archive", Version: "https://github.com/a/b/archive/refs/tags/v3.tar.gz", Retrieved: "2026-08-26", Commit: "def", SHA256: "cafe", License: Licenses{"Apache-2.0"}},
	}
	if problems := verifyProblems(deps, entries); len(problems) != 0 {
		t.Errorf("verifyProblems on up-to-date entries = %v, want none", problems)
	}
	for _, id := range []License{"NOASSERTION", "Apache-2.0 WITH LLVM-exception", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later"} {
		entries[0].License = Licenses{id}
		if problems := verifyProblems(deps, entries); len(problems) != 0 {
			t.Errorf("verifyProblems with explicit %s = %v", id, problems)
		}
	}
	entries[0].License = Licenses{"MIT"}

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
		{Dependency: "a", License: Licenses{"MIT"}},
		{Dependency: "b", License: Licenses{"MPL-2.0"}},
		{Dependency: "c", License: Licenses{"Apache-2.0", "MPL-2.0"}},
		{Dependency: "d", License: Licenses{"GPL-2.0-only"}},
	}
	policy := &Policy{
		AllowedLicenses: []License{"Apache-2.0", "MIT"},
		Exceptions: []Exception{
			{Dependency: "b", License: Licenses{"MPL-2.0"}, ExceptionRationale: "vendored"},
			{Dependency: "c", License: Licenses{"Apache-2.0", "MPL-2.0"}, ExceptionRationale: "notices"},
		},
	}
	if problems := CheckPolicy(entries, policy); len(problems) != 1 || !strings.Contains(problems[0], "d uses disallowed licenses") {
		t.Errorf("CheckPolicy = %v, want a single problem for d", problems)
	}
	// A license mismatch, a stale exception, an unnecessary exception, and
	// the now-uncovered c and d are all flagged.
	policy.Exceptions = []Exception{
		{Dependency: "a", License: Licenses{"MIT"}, ExceptionRationale: "redundant"},
		{Dependency: "b", License: Licenses{"Unlicense"}, ExceptionRationale: "wrong license"},
		{Dependency: "z", License: Licenses{"MPL-2.0"}, ExceptionRationale: "no longer a dependency"},
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

func TestLicenseSourceIdentity(t *testing.T) {
	const artifact = "https://github.com/example/builder/releases/download/v1/tool.tar.gz"
	const commit = "0123456789abcdef0123456789abcdef01234567"
	const source = "https://raw.githubusercontent.com/example/upstream/" + commit + "/COPYING"
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name     string
		url      string
		hash     string
		source   string
		goModule bool
		wantErr  bool
	}{
		{name: "pinned", url: artifact, hash: hash, source: source},
		{name: "automatic", url: artifact, hash: hash},
		{name: "changed artifact", url: artifact + "?changed", hash: hash, source: source, wantErr: true},
		{name: "changed digest", url: artifact, hash: strings.Repeat("a", 64), source: source, wantErr: true},
		{name: "unpinned artifact", url: artifact, source: source, wantErr: true},
		{name: "mutable notice", url: artifact, hash: hash, source: strings.ReplaceAll(source, commit, "main"), wantErr: true},
		{name: "notice traversal", url: artifact, hash: hash, source: strings.ReplaceAll(source, "/COPYING", "/../main/COPYING"), wantErr: true},
		{name: "encoded traversal", url: artifact, hash: hash, source: strings.ReplaceAll(source, "/COPYING", "/%2e%2e/main/COPYING"), wantErr: true},
		{name: "go module", url: artifact, hash: hash, source: source, goModule: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := dep{name: "tool", kind: kindArchive, url: test.url, sha256: test.hash}
			if test.goModule {
				d.kind = kindGoModule
			}
			e := Entry{Version: artifact, SHA256: hash, LicenseSource: test.source}
			got, err := licenseSourceCommit(d, e)
			if (err != nil) != test.wantErr {
				t.Fatalf("licenseSourceCommit = %q, %v; want error %t", got, err, test.wantErr)
			}
			if !test.wantErr && test.source != "" && got != commit {
				t.Fatalf("licenseSourceCommit = %q, want %q", got, commit)
			}
		})
	}
}

func TestVerifyLicenseSource(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	d := dep{name: "tool", kind: kindArchive, url: "https://example.com/tool.tar.gz", sha256: strings.Repeat("a", 64)}
	e := Entry{Dependency: d.name, Version: d.url, SHA256: d.sha256, Retrieved: "2026-10-17", Commit: commit, License: Licenses{gpl2}, LicenseSource: "https://raw.githubusercontent.com/example/upstream/" + commit + "/COPYING"}
	if problems := verifyProblems([]dep{d}, []Entry{e}); len(problems) != 0 {
		t.Fatalf("verifyProblems = %v, want a valid explicit notice", problems)
	}
	e.Commit = strings.Repeat("b", 40)
	if problems := verifyProblems([]dep{d}, []Entry{e}); len(problems) != 1 || !strings.Contains(problems[0], "license_source commit") {
		t.Fatalf("verifyProblems = %v, want mismatched notice commit", problems)
	}
	e.LicenseSource = "https://raw.githubusercontent.com/example/upstream/main/COPYING"
	if problems := verifyProblems([]dep{d}, []Entry{e}); len(problems) != 1 || !strings.Contains(problems[0], "pinned to a full commit") {
		t.Fatalf("verifyProblems = %v, want unpinned notice error", problems)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestReadRepoMapping(t *testing.T) {
	origMakeMod := makeMod
	defer func() { makeMod = origMakeMod }()

	makeMod = func(args ...string) (string, error) {
		return "", errors.New("boom")
	}
	if _, err := readRepoMapping(""); err == nil {
		t.Fatal("readRepoMapping succeeded on makeMod error")
	}

	makeMod = func(args ...string) (string, error) {
		return "no json here", nil
	}
	if _, err := readRepoMapping("hub"); err == nil || !strings.Contains(err.Error(), "no repository mapping JSON") {
		t.Fatalf("readRepoMapping = %v, want missing JSON error", err)
	}

	makeMod = func(args ...string) (string, error) {
		return "{invalid json", nil
	}
	if _, err := readRepoMapping("hub"); err == nil || !strings.Contains(err.Error(), "cannot parse repository mapping") {
		t.Fatalf("readRepoMapping = %v, want parse error", err)
	}
}

func TestEnumerateAndFetchQemuLicenseSource(t *testing.T) {
	origMakeMod := makeMod
	origHTTPClient := httpClient
	defer func() {
		makeMod = origMakeMod
		httpClient = origHTTPClient
	}()

	const (
		depName  = "qemu_user_prebuilt_linux_amd64_aarch64"
		artifact = "https://github.com/hermeticbuild/rules_qemu/releases/download/v0.3.0/qemu.tar.zst"
		sha      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		commit   = "0123456789abcdef0123456789abcdef01234567"
		source   = "https://raw.githubusercontent.com/qemu/qemu/" + commit + "/COPYING"
		gpl2Text = "GNU GENERAL PUBLIC LICENSE Version 2, June 1991"
	)

	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module gvisor.dev/gvisor\n\ngo 1.23\n"), 0644); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(dir, "dependencies.yaml")
	paths := Paths{GoMod: goModPath, YAML: yamlPath}

	graphJSON := `{"dependencies":[],"extensionUsages":[{"key":"@@rules_qemu+//qemu/extension:qemu.bzl%qemu","used_repos":["qemu_user_toolchains"]}]}`
	showRepoOut := "## @@rules_qemu++qemu+arm:\nhttp_archive(\n  urls = [\"" + artifact + "\"],\n  sha256 = \"" + sha + "\",\n)\n"

	for _, tc := range []struct {
		name    string
		rootMap string
		rootErr error
		hubMap  string
		hubErr  error
		wantErr string
	}{
		{
			name:    "root mapping error",
			rootErr: errors.New("root dump failed"),
			wantErr: "root dump failed",
		},
		{
			name:    "missing hub",
			rootMap: `{}`,
			wantErr: "QEMU user toolchain repository is not imported",
		},
		{
			name:    "hub mapping error",
			rootMap: `{"qemu_user_toolchains":"rules_qemu++qemu+hub"}`,
			hubErr:  errors.New("hub dump failed"),
			wantErr: "hub dump failed",
		},
		{
			name:    "empty user archives",
			rootMap: `{"qemu_user_toolchains":"rules_qemu++qemu+hub"}`,
			hubMap:  `{"qemu_system_data_prebuilt_linux_amd64":"rules_qemu++qemu+fw"}`,
			wantErr: "exposes no emulator archives",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeMod = func(args ...string) (string, error) {
				switch args[0] {
				case "graph":
					return graphJSON, nil
				case "dump_repo_mapping":
					if args[1] == "''" {
						return tc.rootMap, tc.rootErr
					}
					return tc.hubMap, tc.hubErr
				default:
					return showRepoOut, nil
				}
			}
			if _, err := enumerate(paths); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("enumerate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	makeMod = func(args ...string) (string, error) {
		switch args[0] {
		case "graph":
			return graphJSON, nil
		case "dump_repo_mapping":
			if args[1] == "''" {
				return `{"qemu_user_toolchains":"rules_qemu++qemu+hub"}`, nil
			}
			return `{"` + depName + `":"rules_qemu++qemu+arm"}`, nil
		case "show_repo":
			return showRepoOut, nil
		default:
			return "", errors.New("unexpected makeMod call")
		}
	}

	seed := []Entry{{
		Dependency:    depName,
		Version:       artifact,
		Retrieved:     "2026-10-17",
		Commit:        commit,
		SHA256:        sha,
		License:       Licenses{gpl2},
		LicenseSource: source,
	}}
	if err := writeEntries(yamlPath, seed); err != nil {
		t.Fatal(err)
	}

	// Successful Fetch preserves LicenseSource and classifies the upstream notice.
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != source {
				return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(gpl2Text)),
			}, nil
		}),
	}
	if err := Fetch(paths); err != nil {
		t.Fatalf("Fetch() = %v, want nil", err)
	}
	got, err := readEntries(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].LicenseSource != source || !slices.Equal(got[0].License, Licenses{gpl2}) {
		t.Fatalf("readEntries after Fetch = %+v, want preserved LicenseSource and GPL-2.0-only", got)
	}

	// Failing notice classification fails Fetch while keeping the explicit entry on disk.
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("unrecognized license text")),
			}, nil
		}),
	}
	if err := Fetch(paths); err == nil {
		t.Fatal("Fetch() succeeded on unclassified notice, want error")
	}
	got, err = readEntries(yamlPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].LicenseSource != source {
		t.Fatalf("readEntries after failed Fetch = %+v, want preserved explicit entry", got)
	}

	// HTTP failure on explicit notice also fails closed.
	httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	}
	if _, err := fetchLicense(dep{name: depName, kind: kindArchive, url: artifact, sha256: sha}, seed[0]); err == nil {
		t.Fatal("fetchLicense() succeeded on 404 notice, want error")
	}
	// Invalid license_source fails before HTTP.
	badEntry := seed[0]
	badEntry.LicenseSource = "https://example.com/bad"
	if _, err := fetchLicense(dep{name: depName, kind: kindArchive, url: artifact, sha256: sha}, badEntry); err == nil {
		t.Fatal("fetchLicense() succeeded on invalid license_source, want error")
	}
}

func TestQemuUserRepoRefs(t *testing.T) {
	// A public hub maps indirect repos that the root module cannot import by
	// apparent name. Firmware and system tools are outside this user-mode audit.
	mapping := map[string]string{
		"qemu_user_prebuilt_linux_amd64_aarch64": "rules_qemu++qemu+arm",
		"qemu_user_prebuilt_linux_arm64_x86_64":  "rules_qemu++qemu+x86",
		"qemu_user_toolchains":                   "rules_qemu++qemu+hub",
		"qemu_system_data_prebuilt_linux_amd64":  "rules_qemu++qemu+firmware",
		"qemu_img_prebuilt_linux_amd64":          "rules_qemu++qemu+img",
	}
	got, err := qemuUserRepoRefs(mapping)
	if err != nil {
		t.Fatal(err)
	}
	want := []repoRef{
		{"@@rules_qemu++qemu+arm", "qemu_user_prebuilt_linux_amd64_aarch64"},
		{"@@rules_qemu++qemu+x86", "qemu_user_prebuilt_linux_arm64_x86_64"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("qemuUserRepoRefs() = %v, want %v", got, want)
	}
	for _, invalid := range []map[string]string{
		{},
		{"qemu_user_toolchains": "rules_qemu++qemu+hub"},
		{"qemu_user_prebuilt_linux_amd64_aarch64": ""},
	} {
		if _, err := qemuUserRepoRefs(invalid); err == nil {
			t.Errorf("qemuUserRepoRefs(%v) succeeded, want missing archive identity error", invalid)
		}
	}
}
