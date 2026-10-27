// Copyright The Isola Authors
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

package installer

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Generation is one installed release under releases/<version>-<digest>.
// Its payload only ever changes back towards its manifest, never to different
// content: running sandboxes resolve runsc and sidecars through this path for
// their whole lifetime.
type Generation struct {
	// Host-view absolute, as stored in state and rendered into configs.
	Path          string
	Version       string
	PayloadSHA512 string
	Files         map[string]extractedFile
}

// Written last during creation, so a directory containing a manifest is
// always a complete extraction.
type installManifest struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Version       string                   `json:"version"`
	PayloadSHA512 string                   `json:"payloadSHA512"`
	Files         map[string]extractedFile `json:"files"`
}

const manifestSchemaVersion = 1

func generationDirName(version, payloadSHA512 string) string {
	return version + "-" + payloadSHA512
}

func (g Generation) runscPath() string { return path.Join(g.Path, runscBinary) }
func (g Generation) shimPath() string  { return path.Join(g.Path, shimBinary) }

// hostDir converts the stored host-view path to one this process can open.
func (g Generation) hostDir(cfg Config) string { return cfg.hostPath(g.Path) }

func (i *Installer) writeManifest(dir string, g Generation) error {
	return writeJSONFile(filepath.Join(dir, manifestFileName), installManifest{
		SchemaVersion: manifestSchemaVersion,
		Version:       g.Version,
		PayloadSHA512: g.PayloadSHA512,
		Files:         g.Files,
	})
}

func (i *Installer) loadGeneration(genPath string) (Generation, error) {
	var m installManifest
	dir := i.cfg.hostPath(genPath)
	// The directory and manifest must be the real thing, not links into
	// content this generation does not own.
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return Generation{}, fmt.Errorf("generation %s is not a directory", genPath)
	}
	if fi, err := os.Lstat(filepath.Join(dir, manifestFileName)); err != nil || !fi.Mode().IsRegular() {
		return Generation{}, fmt.Errorf("generation %s has no regular manifest", genPath)
	}
	if err := readJSONFile(filepath.Join(dir, manifestFileName), &m); err != nil {
		return Generation{}, err
	}
	if len(m.PayloadSHA512) != sha512HexLen || !isHex(m.PayloadSHA512) || m.Version == "" {
		return Generation{}, fmt.Errorf("invalid generation manifest")
	}
	if m.SchemaVersion != manifestSchemaVersion {
		return Generation{}, fmt.Errorf("manifest %s has unsupported schema %d", genPath, m.SchemaVersion)
	}
	if err := validateManifestFiles(m.Files); err != nil {
		return Generation{}, fmt.Errorf("manifest %s: %w", genPath, err)
	}
	raw, err := json.Marshal(m.Files)
	if err != nil {
		return Generation{}, err
	}
	sum := sha512.Sum512(raw)
	if hex.EncodeToString(sum[:]) != m.PayloadSHA512 {
		return Generation{}, fmt.Errorf("manifest payload digest does not match file records")
	}
	if path.Base(genPath) != generationDirName(m.Version, m.PayloadSHA512) {
		return Generation{}, fmt.Errorf("manifest %s does not match its directory name", genPath)
	}
	return Generation{
		Path:          genPath,
		Version:       m.Version,
		PayloadSHA512: m.PayloadSHA512,
		Files:         m.Files,
	}, nil
}

// A tampered manifest must not be able to bless tampered payload.
func validateManifestFiles(files map[string]extractedFile) error {
	for _, required := range []string{runscBinary, shimBinary} {
		if _, ok := files[required]; !ok {
			return fmt.Errorf("missing required file %q", required)
		}
	}
	for name, rec := range files {
		if _, err := normalizeEntryName(name); err != nil {
			return err
		}
		if len(rec.SHA512) != sha512HexLen || !isHex(rec.SHA512) {
			return fmt.Errorf("file %q has a malformed digest", name)
		}
		if rec.Mode != "0755" && rec.Mode != "0644" {
			return fmt.Errorf("file %q has unexpected mode %q", name, rec.Mode)
		}
	}
	return nil
}

// Memoized per reconcile pass: verifying hashes the full ~265MB payload.
func (i *Installer) verifyGenerationCached(g Generation) error {
	if cached, ok := i.verifyCache[g.Path]; ok {
		return cached
	}
	err := i.verifyGeneration(g)
	if i.verifyCache != nil {
		i.verifyCache[g.Path] = err
	}
	return err
}

// Exact-set equality with the manifest.
func (i *Installer) verifyGeneration(g Generation) error {
	dir := g.hostDir(i.cfg)
	for _, d := range []string{i.cfg.hostPath(i.cfg.InstallDir), filepath.Dir(dir), dir} {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("generation directory %q missing or not a directory", d)
		}
		if fi.Mode().Perm() != 0o755 {
			return fmt.Errorf("generation directory %q has mode %04o, expected 0755", d, fi.Mode().Perm())
		}
	}
	for name, want := range g.Files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		// Lstat: a symlink to matching content must not pass as payload, or
		// the generation is no longer self-contained.
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("generation file %q missing or not regular", name)
		}
		if got := fmt.Sprintf("%#o", fi.Mode().Perm()); got != want.Mode {
			return fmt.Errorf("generation file %q has mode %s, manifest says %s", name, got, want.Mode)
		}
		sum, err := fileSHA512(p)
		if err != nil {
			return err
		}
		if sum != want.SHA512 {
			return fmt.Errorf("generation file %q does not match its manifest digest", name)
		}
	}
	return i.checkNoExtraFiles(dir, g.Files)
}

func (i *Installer) checkNoExtraFiles(dir string, files map[string]extractedFile) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == manifestFileName {
			if !d.Type().IsRegular() {
				return fmt.Errorf("generation file %q is not a regular file", rel)
			}
			return nil
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0755 {
				return fmt.Errorf("generation directory %q has mode %04o", rel, info.Mode().Perm())
			}
			for name := range files {
				if strings.HasPrefix(name, rel+"/") {
					return nil
				}
			}
			return fmt.Errorf("generation contains unexpected directory %q", rel)
		}
		if _, ok := files[rel]; !ok && !(d.Type().IsRegular() && strings.HasPrefix(path.Base(rel), tempPrefix)) {
			return fmt.Errorf("generation contains unexpected file %q", rel)
		}
		return nil
	})
}

// Same-directory rename: a shim exec'ing a sidecar sees old or new bytes,
// never truncated ones.
func replaceFromStaging(dest, src string, want extractedFile) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	mode := os.FileMode(0o644)
	if want.Mode == "0755" {
		mode = 0o755
	}
	f, err := os.CreateTemp(filepath.Dir(dest), tempPrefix+filepath.Base(dest)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	_, writeErr := io.Copy(f, in)
	var syncErr error
	if writeErr == nil {
		// The directory fsync after the rename does not make the CONTENT
		// durable.
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err := os.Chmod(tmp, mode); err != nil { // creation modes are umask-filtered
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(dest))
}

// restoreGeneration replaces damaged files with the exact content addressed
// by this generation. Executables are atomically renamed, never truncated.
func (i *Installer) restoreGeneration(g Generation, staging string) error {
	dir := g.hostDir(i.cfg)
	if err := checkDirectoryAncestors(dir); err != nil {
		return err
	}
	directories := map[string]bool{dir: true}
	for name := range g.Files {
		for parent := filepath.Dir(filepath.Join(dir, filepath.FromSlash(name))); parent != dir; parent = filepath.Dir(parent) {
			directories[parent] = true
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	slices.SortFunc(ordered, func(a, b string) int { return len(a) - len(b) })
	for _, directory := range ordered {
		if fi, err := os.Lstat(directory); err == nil && !fi.IsDir() {
			if err := os.Remove(directory); err != nil {
				return err
			}
		}
		if err := ensureDirectory(directory, 0755); err != nil {
			return err
		}
	}
	for name, want := range g.Files {
		dest := filepath.Join(dir, filepath.FromSlash(name))
		if fi, err := os.Lstat(dest); err == nil && fi.Mode().IsRegular() && fmt.Sprintf("%#o", fi.Mode().Perm()) == want.Mode {
			if sum, err := fileSHA512(dest); err == nil && sum == want.SHA512 {
				continue
			}
		}
		if fi, err := os.Lstat(dest); err == nil && fi.IsDir() {
			if err := os.RemoveAll(dest); err != nil {
				return err
			}
		}
		if err := replaceFromStaging(dest, filepath.Join(staging, filepath.FromSlash(name)), want); err != nil {
			return err
		}
	}
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if directories[p] {
				return nil
			}
			if err := os.RemoveAll(p); err != nil {
				return err
			}
			return fs.SkipDir
		}
		if _, ok := g.Files[rel]; ok {
			return nil
		}
		if rel == manifestFileName && d.Type().IsRegular() {
			return nil
		}
		return os.Remove(p)
	}); err != nil {
		return err
	}
	if err := i.writeManifest(dir, g); err != nil {
		return err
	}
	return i.verifyGeneration(g)
}
