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
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/mail"
	"net/url"
	"path"
	"slices"
	"strings"
)

// enumerateWheels follows the imported pip hubs' generated whl_map through
// Bazel's repository mappings. In particular, neither the lockfile nor the
// extension's canonical repository naming scheme is reimplemented here.
func enumerateWheels(repos map[string]repoInfo) ([]dep, error) {
	wheels := make(map[string]repoInfo)
	refs := make(map[string]struct{})
	for ref, repo := range repos {
		switch repo.rule {
		case "whl_library":
			wheels[ref] = repo
		case "hub_repository":
			name := repo.first("name")
			if name == "" {
				return nil, fmt.Errorf("pip hub %s has no canonical name", ref)
			}
			mapping, err := makeMod("dump_repo_mapping", name)
			if err != nil {
				return nil, err
			}
			hubRefs, err := hubWheelRefs(repo, mapping)
			if err != nil {
				return nil, fmt.Errorf("pip hub %s: %w", ref, err)
			}
			for _, r := range hubRefs {
				refs[r] = struct{}{}
			}
		}
	}
	if len(refs) != 0 {
		args := append([]string{"show_repo"}, slices.Sorted(maps.Keys(refs))...)
		out, err := makeMod(args...)
		if err != nil {
			return nil, err
		}
		resolved, err := parseShowRepos(out)
		if err != nil {
			return nil, err
		}
		for ref := range refs {
			repo, ok := resolved[ref]
			if !ok || repo.rule != "whl_library" {
				return nil, fmt.Errorf("pip hub wheel %s did not resolve to whl_library", ref)
			}
			wheels[ref] = repo
		}
	}
	byName := make(map[string]dep)
	for ref, repo := range wheels {
		d, err := wheelDependency(repo)
		if err != nil {
			return nil, fmt.Errorf("wheel %s: %w", ref, err)
		}
		// Several hubs or Python versions can share an identical wheel. A
		// different platform wheel has its own filename and audit entry.
		if old, ok := byName[d.name]; ok && old != d {
			return nil, fmt.Errorf("conflicting wheel artifacts for %s", d.name)
		}
		byName[d.name] = d
	}
	return slices.Collect(maps.Values(byName)), nil // enumerate sorts the complete dependency set.
}

func hubWheelRefs(hub repoInfo, mappingOut string) ([]string, error) {
	start := strings.Index(mappingOut, "{")
	if start < 0 {
		return nil, fmt.Errorf("no JSON in dump_repo_mapping output")
	}
	var mapping map[string]string
	if err := json.Unmarshal([]byte(mappingOut[start:]), &mapping); err != nil {
		return nil, fmt.Errorf("invalid repository mapping: %w", err)
	}
	values, ok := hub.attrs["whl_map"]
	if !ok || len(values)%2 != 0 {
		return nil, fmt.Errorf("missing or malformed whl_map")
	}
	var refs []string
	for i := 1; i < len(values); i += 2 {
		var variants map[string]json.RawMessage
		if err := json.Unmarshal([]byte(values[i]), &variants); err != nil {
			return nil, fmt.Errorf("invalid whl_map for %s: %w", values[i-1], err)
		}
		if len(variants) == 0 {
			return nil, fmt.Errorf("no wheel variants for %s", values[i-1])
		}
		for apparent := range variants {
			canonical := mapping[apparent]
			if canonical == "" {
				return nil, fmt.Errorf("wheel %s is missing from the hub's repository mapping", apparent)
			}
			refs = append(refs, "@@"+canonical)
		}
	}
	slices.Sort(refs)
	return slices.Compact(refs), nil
}

func wheelDependency(repo repoInfo) (dep, error) {
	filename, urls, sum := repo.first("filename"), repo.attrs["urls"], repo.first("sha256")
	if !fs.ValidPath(filename) || strings.ContainsAny(filename, `/\`) || !strings.HasSuffix(filename, ".whl") || len(urls) == 0 {
		return dep{}, fmt.Errorf("audit requires an explicit wheel filename and URL; configure pip.parse with experimental_index_url and download_only=True")
	}
	hash, err := hex.DecodeString(sum)
	if err != nil || len(hash) != sha256.Size {
		return dep{}, fmt.Errorf("wheel %s has no valid SHA256 pin", filename)
	}
	u, err := url.Parse(urls[0])
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return dep{}, fmt.Errorf("wheel %s must have an HTTPS artifact URL without credentials", filename)
	}
	return dep{name: "pypi/" + filename, kind: kindWheel, url: urls[0], sha256: hex.EncodeToString(hash)}, nil
}

// wheelLicenses audits the exact pinned archive. Each distribution metadata
// record, including vendored .dist-info directories, owns its License-File
// declarations. Modern wheels put those files in licenses/; older wheels put
// them directly in .dist-info. Missing or ambiguous declarations fail closed.
func wheelLicenses(body []byte, pin string) (Licenses, error) {
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != pin {
		return nil, fmt.Errorf("wheel SHA256 mismatch: got %x, want %s", sum, pin)
	}
	z, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("invalid wheel ZIP: %w", err)
	}
	files := make(map[string]*zip.File)
	var metadata []string
	rootMetadata := 0
	for _, f := range z.File {
		if _, ok := files[f.Name]; ok {
			return nil, fmt.Errorf("duplicate wheel member %s", f.Name)
		}
		files[f.Name] = f
		if strings.HasSuffix(f.Name, ".dist-info/METADATA") {
			metadata = append(metadata, f.Name)
			if strings.Count(f.Name, "/") == 1 {
				rootMetadata++
			}
		}
	}
	if rootMetadata != 1 {
		return nil, fmt.Errorf("wheel has %d top-level METADATA files, want one", rootMetadata)
	}
	var licenses Licenses
	for _, name := range metadata {
		data, err := readWheelFile(files[name])
		if err != nil {
			return nil, err
		}
		message, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", name, err)
		}
		declared := message.Header["License-File"]
		if message.Header.Get("Name") == "" || message.Header.Get("Version") == "" || len(declared) == 0 {
			return nil, fmt.Errorf("%s must declare Name, Version and License-File", name)
		}
		var texts []string
		for _, license := range declared {
			if !fs.ValidPath(license) || strings.Contains(license, `\`) {
				return nil, fmt.Errorf("invalid License-File %q in %s", license, name)
			}
			dir := path.Dir(name)
			modern, legacy := files[dir+"/licenses/"+license], files[dir+"/"+license]
			if (modern == nil) == (legacy == nil) {
				return nil, fmt.Errorf("missing or ambiguous License-File %q in %s", license, name)
			}
			if modern == nil {
				modern = legacy
			}
			text, err := readWheelFile(modern)
			if err != nil {
				return nil, err
			}
			texts = append(texts, string(text))
		}
		// A distribution can split its license across several files, such
		// as a pointer LICENSE alongside LICENSE.APACHE and LICENSE.BSD.
		ids, err := classify(strings.Join(texts, "\n"))
		if err != nil {
			return nil, fmt.Errorf("licenses declared by %s: %w", name, err)
		}
		licenses = append(licenses, ids...)
	}
	slices.Sort(licenses)
	return slices.Compact(licenses), nil
}

func readWheelFile(f *zip.File) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", f.Name, err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", f.Name, err)
	}
	return b, nil
}
