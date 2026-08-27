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

// Package licensecheck audits the licenses of gVisor's external dependencies.
//
// Dependencies are enumerated by asking Bazel (`make mod`, which wraps `bazel
// mod` in the dockerized build environment): the root module's direct
// bazel_deps, the http_archive/http_file repos declared in MODULE.bazel, and
// the Go repos imported from the go_deps extension, unioned with go.mod's
// requirements. Fetch downloads each dependency's license text, from the Go
// module proxy for Go modules and from GitHub for everything else, classifies
// it, and records it in a YAML file. Verify checks that the YAML file has an
// entry for every dependency, without fetching any licenses.
//
// Entries whose license cannot be fetched automatically (e.g.
// @google_root_pem) are maintained by hand: Fetch preserves an existing entry
// whenever fetching fails.
package licensecheck

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	yaml "gopkg.in/yaml.v3"
)

// Paths locates the audit's inputs and output, relative to the repo root.
type Paths struct {
	GoMod  string
	YAML   string
	Policy string
}

// Entry records the license of a single dependency.
type Entry struct {
	Dependency string   `yaml:"dependency"`
	Version    string   `yaml:"version"`
	Retrieved  string   `yaml:"retrieved"`
	Commit     string   `yaml:"commit"`
	SHA256     string   `yaml:"sha256"`
	License    Licenses `yaml:"license"`
}

// License is an SPDX license identifier (https://spdx.org/licenses/), one of
// knownLicenses.
type License string

const (
	apache2     License = "Apache-2.0"
	apache2LLVM License = "Apache-2.0 WITH LLVM-exception"
	bsd2        License = "BSD-2-Clause"
	bsd3        License = "BSD-3-Clause"
	bsd4        License = "BSD-4-Clause"
	gpl2        License = "GPL-2.0-only"
	gpl3        License = "GPL-3.0-only"
	isc         License = "ISC"
	lgpl21      License = "LGPL-2.1-only"
	lgpl3       License = "LGPL-3.0-only"
	mit         License = "MIT"
	mpl2        License = "MPL-2.0"
	unlicense   License = "Unlicense"
	// noAssertion is the SPDX token for dependencies to which no software
	// license applies, e.g. a certificate bundle.
	noAssertion License = "NOASSERTION"
)

// knownLicenses is the set of known license identifiers.
var knownLicenses = map[License]bool{
	apache2:     true,
	apache2LLVM: true,
	bsd2:        true,
	bsd3:        true,
	bsd4:        true,
	gpl2:        true,
	gpl3:        true,
	isc:         true,
	lgpl21:      true,
	lgpl3:       true,
	mit:         true,
	mpl2:        true,
	unlicense:   true,
	noAssertion: true,
}

// Licenses is the sorted set of licenses that apply to a dependency. It
// marshals as a plain string when there is a single license and as a list
// otherwise.
type Licenses []License

// String implements fmt.Stringer.String.
func (l Licenses) String() string {
	s := make([]string, len(l))
	for i, license := range l {
		s[i] = string(license)
	}
	return strings.Join(s, ", ")
}

// MarshalYAML implements yaml.Marshaler.MarshalYAML.
func (l Licenses) MarshalYAML() (any, error) {
	if len(l) == 1 {
		return string(l[0]), nil
	}
	s := make([]string, len(l))
	for i, license := range l {
		s[i] = string(license)
	}
	return s, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.UnmarshalYAML.
func (l *Licenses) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*l = Licenses{License(s)}
		return nil
	case yaml.SequenceNode:
		var s []string
		if err := node.Decode(&s); err != nil {
			return err
		}
		if len(s) < 2 {
			return errors.New("a license list must have at least two entries; use a plain string for a single license")
		}
		*l = make(Licenses, len(s))
		for i, license := range s {
			(*l)[i] = License(license)
		}
		return nil
	default:
		return errors.New("license must be a string or a list of strings")
	}
}

type depKind int

const (
	kindGoModule depKind = iota
	kindArchive
)

// dep is a single external dependency.
type dep struct {
	name    string
	kind    depKind
	version string // kindGoModule.
	url     string // kindArchive.
	sha256  string // kindArchive: the hash Bazel pins for the archive.
}

// source identifies the audited version of a dependency: the Go module
// version, or the source archive URL.
func (d dep) source() string {
	if d.kind == kindGoModule {
		return d.version
	}
	return d.url
}

const (
	yamlHeader = `# Licenses of gVisor's external dependencies, as declared in MODULE.bazel and
# go.mod.
# Regenerate with: make run TARGETS=//tools/licensecheck/main:licensecheck ARGS=--mode=fetch
# Check completeness with ARGS=--mode=verify.
# Entries whose license cannot be fetched automatically are maintained by hand and preserved
# by --mode=fetch, so you can hand-edit the file for these.
`
	dateFormat   = "2006-01-02"
	fetchWorkers = 8
)

// Fetch retrieves the license of every dependency and rewrites the YAML file.
func Fetch(p Paths) error {
	deps, err := enumerate(p)
	if err != nil {
		return err
	}
	old, err := readEntries(p.YAML)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	oldByName := make(map[string]Entry)
	for _, e := range old {
		oldByName[e.Dependency] = e
	}

	type result struct {
		fetched *fetched
		err     error
	}
	results := make([]result, len(deps))
	sem := make(chan struct{}, fetchWorkers)
	var wg sync.WaitGroup
	for i, d := range deps {
		wg.Add(1)
		go func(i int, d dep) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f, err := fetchLicense(d)
			results[i] = result{f, err}
		}(i, d)
	}
	wg.Wait()

	today := time.Now().UTC().Format(dateFormat)
	var entries []Entry
	var failed []string
	for i, d := range deps {
		r := results[i]
		if r.err != nil {
			if e, ok := oldByName[d.name]; ok && len(e.License) > 0 {
				fmt.Fprintf(os.Stderr, "%-60s %s (kept existing entry: %v)\n", d.name, e.License, r.err)
				entries = append(entries, e)
				continue
			}
			fmt.Fprintf(os.Stderr, "%-60s FAILED: %v\n", d.name, r.err)
			failed = append(failed, d.name)
			continue
		}
		e := Entry{
			Dependency: d.name,
			Version:    d.source(),
			Retrieved:  today,
			Commit:     r.fetched.commit,
			SHA256:     r.fetched.sha256,
			License:    r.fetched.license,
		}
		// Keep the old retrieval date when nothing changed, so that re-running
		// fetch does not churn the file.
		if o, ok := oldByName[d.name]; ok && o.Version == e.Version && o.Commit == e.Commit &&
			o.SHA256 == e.SHA256 && slices.Equal(o.License, e.License) {
			e.Retrieved = o.Retrieved
		}
		fmt.Fprintf(os.Stderr, "%-60s %s\n", d.name, e.License)
		entries = append(entries, e)
	}
	if err := writeEntries(p.YAML, entries); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("cannot fetch licenses for %s; add entries to %s by hand", strings.Join(failed, ", "), p.YAML)
	}
	return nil
}

// Verify checks that the YAML file has a well-formed, up-to-date entry for
// every dependency and no entries for dependencies that no longer exist.
func Verify(p Paths) error {
	deps, err := enumerate(p)
	if err != nil {
		return err
	}
	entries, err := readEntries(p.YAML)
	if err != nil {
		return err
	}
	policy, err := ReadPolicy(p.Policy)
	if err != nil {
		return err
	}
	problems := append(verifyProblems(deps, entries), CheckPolicy(entries, policy)...)
	if len(problems) > 0 {
		sort.Strings(problems)
		for _, problem := range problems {
			fmt.Fprintln(os.Stderr, problem)
		}
		return fmt.Errorf("%d problems; regenerate %s with licensecheck --mode=fetch, or amend %s", len(problems), p.YAML, p.Policy)
	}
	fmt.Printf("all %d dependencies have up-to-date license entries that conform to %s\n", len(deps), p.Policy)
	return nil
}

// verifyProblems returns one problem per missing, malformed, out-of-date, or
// stale entry.
func verifyProblems(deps []dep, entries []Entry) []string {
	byName := make(map[string]Entry)
	var problems []string
	for _, e := range entries {
		if _, ok := byName[e.Dependency]; ok {
			problems = append(problems, fmt.Sprintf("duplicate entry for %s", e.Dependency))
		}
		byName[e.Dependency] = e
	}
	depSet := make(map[string]bool)
	for _, d := range deps {
		depSet[d.name] = true
		e, ok := byName[d.name]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("missing entry for %s", d.name))
		case len(e.License) == 0:
			problems = append(problems, fmt.Sprintf("%s has no license", d.name))
		default:
			if e.Version != d.source() {
				problems = append(problems, fmt.Sprintf("%s was audited at %q, but is now %q", d.name, e.Version, d.source()))
			}
			// Archive hashes are pinned by Bazel, so verify can cross-check
			// them offline. Go module hashes are only computed by fetch.
			if d.sha256 != "" && e.SHA256 != d.sha256 {
				problems = append(problems, fmt.Sprintf("%s was audited with sha256 %q, but is now pinned to %q", d.name, e.SHA256, d.sha256))
			}
			for i, license := range e.License {
				if !knownLicenses[license] {
					problems = append(problems, fmt.Sprintf("%s has unknown license %q", d.name, license))
				}
				if i > 0 && e.License[i-1] >= license {
					problems = append(problems, fmt.Sprintf("licenses of %s are not sorted and unique", d.name))
					break
				}
			}
			if _, err := time.Parse(dateFormat, e.Retrieved); err != nil {
				problems = append(problems, fmt.Sprintf("%s has invalid retrieval date %q", d.name, e.Retrieved))
			}
		}
	}
	for name := range byName {
		if !depSet[name] {
			problems = append(problems, fmt.Sprintf("stale entry for %s, which is no longer a dependency", name))
		}
	}
	return problems
}

// enumerate returns all external dependencies, sorted by name.
func enumerate(p Paths) ([]dep, error) {
	graphOut, err := makeMod("graph", "--depth", "1", "--extension_info=all", "--output", "json")
	if err != nil {
		return nil, err
	}
	graph, err := parseModGraph(graphOut)
	if err != nil {
		return nil, err
	}
	// refs are the repos to audit: modules as name@version, everything else
	// by apparent repo name.
	type repoRef struct {
		ref, name string
	}
	var refs []repoRef
	for _, m := range graph.Dependencies {
		refs = append(refs, repoRef{m.Key, m.Name})
	}
	for _, u := range graph.ExtensionUsages {
		switch {
		case strings.HasPrefix(u.Key, "@@//:MODULE.bazel%") &&
			(strings.HasSuffix(u.Key, " http_archive") || strings.HasSuffix(u.Key, " http_file")):
			// http_archive/http_file declared directly in MODULE.bazel.
		case strings.HasSuffix(u.Key, "%go_deps"):
			// Go repos imported from the gazelle go_deps extension.
		default:
			// Toolchain extensions (crosstool, llvm_zlib, python, go_sdk,
			// ...) are not audited.
			continue
		}
		for _, r := range u.UsedRepos {
			refs = append(refs, repoRef{"@" + r, r})
		}
	}
	refNames := make([]string, 0, len(refs)+1)
	refNames = append(refNames, "show_repo")
	for _, r := range refs {
		refNames = append(refNames, r.ref)
	}
	showOut, err := makeMod(refNames...)
	if err != nil {
		return nil, err
	}
	repos, err := parseShowRepos(showOut)
	if err != nil {
		return nil, err
	}

	goModData, err := os.ReadFile(p.GoMod)
	if err != nil {
		return nil, err
	}
	goMod, err := modfile.Parse(p.GoMod, goModData, nil)
	if err != nil {
		return nil, err
	}
	goVersions := make(map[string]string)
	for _, r := range goMod.Require {
		goVersions[r.Mod.Path] = r.Mod.Version
	}

	var deps []dep
	for _, r := range refs {
		repo, ok := repos[r.ref]
		if !ok {
			return nil, fmt.Errorf("bazel mod show_repo did not report %s", r.ref)
		}
		switch repo.rule {
		case "go_repository":
			path, version := repo.first("importpath"), repo.first("version")
			if path == "" || version == "" {
				return nil, fmt.Errorf("go_repository %s has no importpath or version", r.name)
			}
			// Bazel resolves Go modules across go.mod and go_deps.module
			// declarations; for modules in both, pick the higher version.
			if v, ok := goVersions[path]; !ok || semver.Compare(version, v) > 0 {
				goVersions[path] = version
			}
		case "http_archive", "http_file":
			urls := append(repo.attrs["url"], repo.attrs["urls"]...)
			if len(urls) == 0 {
				return nil, fmt.Errorf("%s %s has no URL", repo.rule, r.name)
			}
			deps = append(deps, dep{name: r.name, kind: kindArchive, url: pickURL(urls), sha256: repoSHA256(repo)})
		case "local_repository", "new_local_repository":
			// Local paths are part of the gVisor checkout, not external
			// dependencies.
		default:
			return nil, fmt.Errorf("unsupported repository rule %s for %s", repo.rule, r.name)
		}
	}
	for path, version := range goVersions {
		deps = append(deps, dep{name: path, kind: kindGoModule, version: version})
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].name < deps[j].name })
	for i := 1; i < len(deps); i++ {
		if deps[i].name == deps[i-1].name {
			return nil, fmt.Errorf("duplicate dependency name %q", deps[i].name)
		}
	}
	return deps, nil
}

// makeMod runs `make mod TARGETS="..."`, which wraps `bazel mod`.
func makeMod(args ...string) (string, error) {
	cmd := exec.Command("make", "-s", "mod", "OPTIONS=", "TARGETS="+strings.Join(args, " "))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cannot run make mod %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// modGraph is the subset of `bazel mod graph --output json` that enumerate
// uses.
type modGraph struct {
	Dependencies []struct {
		Key  string `json:"key"`  // "name@version".
		Name string `json:"name"` // Module name.
	} `json:"dependencies"`
	ExtensionUsages []struct {
		Key       string   `json:"key"`
		UsedRepos []string `json:"used_repos"`
	} `json:"extensionUsages"`
}

// parseModGraph parses `bazel mod graph --output json` output, skipping any
// container-management noise preceding the JSON document.
func parseModGraph(out string) (*modGraph, error) {
	start := strings.Index(out, "{")
	if start < 0 {
		return nil, fmt.Errorf("no JSON in bazel mod graph output %q", out)
	}
	var graph modGraph
	if err := json.Unmarshal([]byte(out[start:]), &graph); err != nil {
		return nil, fmt.Errorf("cannot parse bazel mod graph output: %w", err)
	}
	return &graph, nil
}

// repoInfo is one repo definition reported by `bazel mod show_repo`: the
// repository rule name and, for each attribute, the string literals in its
// value.
type repoInfo struct {
	rule  string
	attrs map[string][]string
}

func (r repoInfo) first(attr string) string {
	if v := r.attrs[attr]; len(v) > 0 {
		return v[0]
	}
	return ""
}

var (
	repoHeaderRE = regexp.MustCompile(`(?m)^## (.+):$`)
	repoRuleRE   = regexp.MustCompile(`^([A-Za-z_]\w*)\($`)
	repoAttrRE   = regexp.MustCompile(`^  (\w+) = (.*),$`)
	quotedRE     = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)
)

// parseShowRepos parses `bazel mod show_repo` output into one repoInfo per
// "## <ref>:" section.
func parseShowRepos(out string) (map[string]repoInfo, error) {
	repos := make(map[string]repoInfo)
	headers := repoHeaderRE.FindAllStringSubmatchIndex(out, -1)
	for i, h := range headers {
		ref := out[h[2]:h[3]]
		end := len(out)
		if i+1 < len(headers) {
			end = headers[i+1][0]
		}
		info := repoInfo{attrs: make(map[string][]string)}
		for _, line := range strings.Split(out[h[1]:end], "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if m := repoRuleRE.FindStringSubmatch(line); m != nil && info.rule == "" {
				info.rule = m[1]
				continue
			}
			if m := repoAttrRE.FindStringSubmatch(line); m != nil {
				var values []string
				for _, q := range quotedRE.FindAllStringSubmatch(m[2], -1) {
					values = append(values, q[1])
				}
				info.attrs[m[1]] = values
			}
		}
		if info.rule == "" {
			return nil, fmt.Errorf("no repository rule in show_repo output for %s", ref)
		}
		repos[ref] = info
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no repos in bazel mod show_repo output %q", out)
	}
	return repos, nil
}

// pickURL returns the first URL whose license source is known, defaulting to
// the first URL.
func pickURL(urls []string) string {
	for _, u := range urls {
		if _, _, _, err := parseGitHubURL(u); err == nil {
			return u
		}
	}
	return urls[0]
}

// repoSHA256 returns the hex sha256 that Bazel pins for an archive repo,
// from its sha256 or "sha256-"-prefixed integrity attribute.
// Empty string if the repo is unpinned (e.g. @google_root_pem).
func repoSHA256(r repoInfo) string {
	if s := r.first("sha256"); s != "" {
		return s
	}
	if integrity := r.first("integrity"); strings.HasPrefix(integrity, "sha256-") {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha256-")); err == nil {
			return hex.EncodeToString(b)
		}
	}
	return ""
}

const goProxy = "https://proxy.golang.org"

var (
	errNotFound = errors.New("not found")
	httpClient  = &http.Client{Timeout: 2 * time.Minute}
)

// httpGet fetches a URL, retrying transient failures once. 404 and 410 are
// permanent and reported as errNotFound.
func httpGet(url string, header map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "gvisor.dev licensecheck")
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			return nil, fmt.Errorf("%s: %w", url, errNotFound)
		case resp.StatusCode != http.StatusOK:
			lastErr = fmt.Errorf("GET %s: %s", url, resp.Status)
		default:
			return body, nil
		}
	}
	return nil, lastErr
}

// fetched is the result of fetching one dependency's license.
type fetched struct {
	commit  string
	sha256  string
	license Licenses
}

// fetchLicense returns the upstream commit, artifact hash, and licenses of a
// dependency.
func fetchLicense(d dep) (*fetched, error) {
	if d.kind == kindGoModule {
		return fetchGoModule(d.name, d.version)
	}
	f, err := fetchGitHub(d.url)
	if err != nil {
		return nil, err
	}
	f.sha256 = d.sha256
	return f, nil
}

// licenseFileNames are candidate top-level license files, in priority order.
var licenseFileNames = []string{
	"LICENSE", "LICENSE.txt", "LICENSE.md", "LICENSE.TXT", "LICENSE.MIT",
	"LICENSE-APACHE-2.0.txt", "LICENCE", "COPYING", "License", "license.md",
}

var pseudoVersionRE = regexp.MustCompile(`\d{14}-([0-9a-f]{12})$`)

// fetchGoModule downloads a module from the Go module proxy and classifies
// the license file at its root.
func fetchGoModule(path, version string) (*fetched, error) {
	escPath, err := module.EscapePath(path)
	if err != nil {
		return nil, err
	}
	escVersion, err := module.EscapeVersion(version)
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s/%s/@v/%s", goProxy, escPath, escVersion)
	var commit string
	if body, err := httpGet(base+".info", nil); err == nil {
		var info struct {
			Origin struct{ Hash string }
		}
		if json.Unmarshal(body, &info) == nil {
			commit = info.Origin.Hash
		}
	}
	if commit == "" {
		if m := pseudoVersionRE.FindStringSubmatch(version); m != nil {
			commit = m[1]
		}
	}
	// Older modules have no Origin metadata in the proxy; for GitHub-hosted
	// ones, fall back to resolving the version tag. Best-effort: the commit
	// stays empty if this fails.
	if commit == "" && strings.HasPrefix(path, "github.com/") {
		prefix, _, _ := module.SplitPathVersion(path)
		if parts := strings.SplitN(prefix, "/", 4); len(parts) >= 3 {
			tag, _, _ := strings.Cut(version, "+")
			if len(parts) == 4 {
				// Tags of modules in a subdirectory are prefixed with it.
				tag = parts[3] + "/" + tag
			}
			if c, err := resolveGitHubCommit(parts[1], parts[2], tag); err == nil {
				commit = c
			}
		}
	}
	zipBody, err := httpGet(base+".zip", nil)
	if err != nil {
		return nil, fmt.Errorf("cannot download module zip: %w", err)
	}
	zipSum := sha256.Sum256(zipBody)
	zipReader, err := zip.NewReader(bytes.NewReader(zipBody), int64(len(zipBody)))
	if err != nil {
		return nil, fmt.Errorf("cannot read module zip: %w", err)
	}
	rootFiles := make(map[string]*zip.File)
	prefix := path + "@" + version + "/"
	for _, f := range zipReader.File {
		if rest, ok := strings.CutPrefix(f.Name, prefix); ok && !strings.Contains(rest, "/") {
			rootFiles[rest] = f
		}
	}
	for _, name := range licenseFileNames {
		f, ok := rootFiles[name]
		if !ok {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		text, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, err
		}
		license, err := classify(string(text))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return &fetched{commit: commit, sha256: hex.EncodeToString(zipSum[:]), license: license}, nil
	}
	return nil, errors.New("no license file at module root")
}

var githubURLRegexps = []*regexp.Regexp{
	regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/`),
	regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/archive/refs/tags/(.+?)\.(?:tar\.gz|tar\.xz|tar\.bz2|zip)$`),
	regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+)/archive/(.+?)\.(?:tar\.gz|tar\.xz|tar\.bz2|zip)$`),
	regexp.MustCompile(`^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/`),
}

// parseGitHubURL extracts (owner, repo, ref) from the archive and raw-file
// URL used by MODULE.bazel and the Bazel Central Registry.
func parseGitHubURL(url string) (owner, repo, ref string, err error) {
	for _, re := range githubURLRegexps {
		if m := re.FindStringSubmatch(url); m != nil {
			return m[1], m[2], m[3], nil
		}
	}
	return "", "", "", fmt.Errorf("cannot determine license source for %q", url)
}

// fetchGitHub resolves a source URL to a GitHub repo and classifies the
// license file at its root.
func fetchGitHub(url string) (*fetched, error) {
	owner, repo, ref, err := parseGitHubURL(url)
	if err != nil {
		return nil, err
	}
	commit, err := resolveGitHubCommit(owner, repo, ref)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve commit for %s/%s@%s: %w", owner, repo, ref, err)
	}
	for _, name := range licenseFileNames {
		body, err := httpGet(fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, name), nil)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		license, err := classify(string(body))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return &fetched{commit: commit, license: license}, nil
	}
	return nil, fmt.Errorf("no license file in %s/%s@%s", owner, repo, ref)
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// resolveGitHubCommit resolves a tag or abbreviated hash to a full commit
// hash. GITHUB_TOKEN, if set, raises the API rate limit.
func resolveGitHubCommit(owner, repo, ref string) (string, error) {
	if commitRE.MatchString(ref) {
		return ref, nil
	}
	header := map[string]string{"Accept": "application/vnd.github.sha"}
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		header["Authorization"] = "Bearer " + token
	}
	body, err := httpGet(fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, ref), header)
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(body))
	if !commitRE.MatchString(commit) {
		return "", fmt.Errorf("unexpected GitHub API response %q", commit)
	}
	return commit, nil
}

// classify maps license text to the set of licenses it contains.
// Detection looks for phrases unique to each license and reports all that
// match. The GNU patterns match the dated titles of the full license texts,
// so that passing references (e.g. in MPL-2.0's "Secondary License" clause)
// do not trigger them.
func classify(text string) (Licenses, error) {
	t := strings.ToLower(strings.Join(strings.Fields(text), " "))
	var ids Licenses
	if strings.Contains(t, "apache license") && strings.Contains(t, "version 2.0") {
		if strings.Contains(t, "llvm exceptions") {
			ids = append(ids, apache2LLVM)
		} else {
			ids = append(ids, apache2)
		}
	}
	if strings.Contains(t, "permission is hereby granted, free of charge") {
		ids = append(ids, mit)
	}
	if strings.Contains(t, "redistribution and use in source and binary forms") {
		switch {
		case strings.Contains(t, "all advertising materials"):
			ids = append(ids, bsd4)
		case strings.Contains(t, "neither the name"):
			ids = append(ids, bsd3)
		default:
			ids = append(ids, bsd2)
		}
	}
	if strings.Contains(t, "mozilla public license version 2.0") {
		ids = append(ids, mpl2)
	}
	if strings.Contains(t, "gnu lesser general public license version 2.1, february 1999") {
		ids = append(ids, lgpl21)
	}
	if strings.Contains(t, "gnu lesser general public license version 3, 29 june 2007") {
		ids = append(ids, lgpl3)
	}
	if strings.Contains(t, "gnu general public license version 2, june 1991") {
		ids = append(ids, gpl2)
	}
	if strings.Contains(t, "gnu general public license version 3, 29 june 2007") {
		ids = append(ids, gpl3)
	}
	if strings.Contains(t, "permission to use, copy, modify") && strings.Contains(t, "distribute this software for any purpose") {
		ids = append(ids, isc)
	}
	if strings.Contains(t, "this is free and unencumbered software") {
		ids = append(ids, unlicense)
	}
	if len(ids) == 0 {
		return nil, errors.New("cannot classify license text")
	}
	slices.Sort(ids)
	return ids, nil
}

// Policy is a dependency licensing policy (governance/licensing.yaml).
type Policy struct {
	AllowedLicenses []License   `yaml:"allowed_licenses"`
	Exceptions      []Exception `yaml:"exceptions"`
}

// Exception allows one dependency to use licenses outside
// Policy.AllowedLicenses. License must match the dependency's entry exactly,
// so that license changes appear during review.
type Exception struct {
	Dependency         string   `yaml:"dependency"`
	License            Licenses `yaml:"license"`
	ExceptionRationale string   `yaml:"exception_rationale"`
}

// ReadPolicy loads a licensing policy file.
func ReadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &policy, nil
}

// CheckPolicy returns a problem for every dependency whose licenses are
// neither all in policy.AllowedLicenses nor covered by an exception, and for
// every malformed, stale, or unnecessary exception.
func CheckPolicy(entries []Entry, policy *Policy) []string {
	allowed := make(map[License]bool)
	for _, license := range policy.AllowedLicenses {
		allowed[license] = true
	}
	conforms := func(l Licenses) bool {
		for _, license := range l {
			if !allowed[license] {
				return false
			}
		}
		return len(l) > 0
	}
	byName := make(map[string]Entry)
	for _, e := range entries {
		byName[e.Dependency] = e
	}
	var problems []string
	exceptions := make(map[string]bool)
	for i, x := range policy.Exceptions {
		if exceptions[x.Dependency] {
			problems = append(problems, fmt.Sprintf("duplicate exception for %s", x.Dependency))
		}
		exceptions[x.Dependency] = true
		if i > 0 && policy.Exceptions[i-1].Dependency >= x.Dependency {
			problems = append(problems, fmt.Sprintf("exceptions are not sorted by dependency at %s", x.Dependency))
		}
		if x.ExceptionRationale == "" {
			problems = append(problems, fmt.Sprintf("exception for %s has no rationale", x.Dependency))
		}
		e, ok := byName[x.Dependency]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("exception for %s, which is not a dependency", x.Dependency))
		case !slices.Equal(x.License, e.License):
			problems = append(problems, fmt.Sprintf("exception for %s lists licenses %v, but the dependency uses %v", x.Dependency, x.License, e.License))
		case conforms(e.License):
			problems = append(problems, fmt.Sprintf("unnecessary exception for %s, whose licenses are all allowed", x.Dependency))
		}
	}
	for _, e := range entries {
		if !conforms(e.License) && !exceptions[e.Dependency] {
			problems = append(problems, fmt.Sprintf("%s uses disallowed licenses %v and has no exception in the policy", e.Dependency, e.License))
		}
	}
	return problems
}

// readEntries loads the YAML file.
func readEntries(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return entries, nil
}

// writeEntries writes the YAML file.
func writeEntries(path string, entries []Entry) error {
	data, err := yaml.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(yamlHeader), data...), 0644)
}
