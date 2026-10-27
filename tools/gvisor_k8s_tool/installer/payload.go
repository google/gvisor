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
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	runscBinary      = "runsc"
	shimBinary       = "containerd-shim-runsc-v1"
	manifestFileName = ".manifest.json"
	tempPrefix       = ".gvisor-tmp."
	sha512HexLen     = sha512.Size * 2
)

type extractedFile struct {
	SHA512 string `json:"sha512"`
	Mode   string `json:"mode"`
}

func isHex(s string) bool { _, err := hex.DecodeString(s); return err == nil }
func normalizeEntryName(name string) (string, error) {
	if !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name {
		return "", fmt.Errorf("invalid payload path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == manifestFileName || strings.HasPrefix(part, tempPrefix) {
			return "", fmt.Errorf("reserved payload path %q", name)
		}
	}
	return name, nil
}

var runscVersionRe = regexp.MustCompile(`runsc version (\S+)`)

func runscReportedVersion(ctx context.Context, binPath string) (string, error) {
	out, err := exec.CommandContext(ctx, binPath, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w (%s)", binPath, err, truncateOutput(out))
	}
	m := runscVersionRe.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("cannot parse runsc --version: %s", truncateOutput(out))
	}
	return strings.TrimPrefix(string(m[1]), "release-"), nil
}

func payloadManifest(ctx context.Context, dir string) (map[string]extractedFile, string, error) {
	files := make(map[string]extractedFile)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name, err := normalizeEntryName(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("payload %q is not a regular file", name)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.Size() == 0 {
			return fmt.Errorf("empty payload file %q", name)
		}
		sum, err := fileSHA512(p)
		if err != nil {
			return err
		}
		mode := "0644"
		if fi.Mode().Perm()&0111 != 0 {
			mode = "0755"
		}
		files[name] = extractedFile{SHA512: sum, Mode: mode}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if err := validateManifestFiles(files); err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(files)
	if err != nil {
		return nil, "", err
	}
	sum := sha512.Sum512(raw)
	return files, hex.EncodeToString(sum[:]), nil
}

func (i *Installer) ensureGeneration(ctx context.Context) (Generation, bool, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return Generation{}, false, fmt.Errorf("only Linux amd64 and arm64 are supported")
	}
	files, digest, err := payloadManifest(ctx, i.cfg.PayloadDir)
	if err != nil {
		return Generation{}, false, err
	}
	version, err := runscReportedVersion(ctx, filepath.Join(i.cfg.PayloadDir, runscBinary))
	if err != nil {
		return Generation{}, false, err
	}
	if len(version) > 63 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(version) {
		return Generation{}, false, fmt.Errorf("invalid runsc version %q", version)
	}
	i.cfg.Version = version
	g := Generation{
		Path:          path.Join(i.cfg.releasesDir(), generationDirName(version, digest)),
		Version:       version,
		PayloadSHA512: digest,
		Files:         files,
	}
	releases := i.cfg.hostPath(i.cfg.releasesDir())
	if err := ensureDirectory(i.cfg.hostPath(i.cfg.InstallDir), 0755); err != nil {
		return Generation{}, false, err
	}
	if err := ensureDirectory(releases, 0755); err != nil {
		return Generation{}, false, err
	}
	repair := false
	if fi, err := os.Lstat(g.hostDir(i.cfg)); err == nil {
		if !fi.IsDir() {
			return Generation{}, false, fmt.Errorf("generation path is not a real directory")
		}
		loaded, loadErr := i.loadGeneration(g.Path)
		if loadErr == nil && loaded.PayloadSHA512 == digest && i.verifyGeneration(loaded) == nil {
			i.markVerified(loaded)
			return loaded, false, nil
		}
		repair = true
	} else if !os.IsNotExist(err) {
		return Generation{}, false, err
	}
	staging, err := os.MkdirTemp(releases, tempPrefix+"stage-")
	if err != nil {
		return Generation{}, false, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0755); err != nil {
		return Generation{}, false, err
	}
	for name, want := range files {
		dest := filepath.Join(staging, filepath.FromSlash(name))
		if err := ensureDirectory(filepath.Dir(dest), 0755); err != nil {
			return Generation{}, false, err
		}
		if err := replaceFromStaging(dest, filepath.Join(i.cfg.PayloadDir, filepath.FromSlash(name)), want); err != nil {
			return Generation{}, false, err
		}
	}
	_, stagedDigest, err := payloadManifest(ctx, staging)
	if err != nil {
		return Generation{}, false, err
	}
	if stagedDigest != digest {
		return Generation{}, false, fmt.Errorf("staged payload differs from image manifest")
	}
	if repair {
		if err := i.restoreGeneration(g, staging); err != nil {
			return Generation{}, false, err
		}
		i.markVerified(g)
		return g, true, nil
	}
	if err := i.writeManifest(staging, g); err != nil {
		return Generation{}, false, err
	}
	if err := os.Rename(staging, g.hostDir(i.cfg)); err != nil {
		return Generation{}, false, err
	}
	if err := syncDir(releases); err != nil {
		return Generation{}, false, err
	}
	if err := i.verifyGeneration(g); err != nil {
		return Generation{}, false, err
	}
	i.markVerified(g)
	return g, true, nil
}

func checkDirectoryAncestors(dir string) error {
	for p := dir; p != "/" && p != "."; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a real directory", p)
		}
	}
	return nil
}

func ensureDirectory(dir string, mode os.FileMode) error {
	if err := checkDirectoryAncestors(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

func (i *Installer) markVerified(g Generation) {
	if i.verifyCache != nil {
		i.verifyCache[g.Path] = nil
	}
}

func fileSHA512(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readJSONFile(p string, v any) error {
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSONFile(p string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(p, data)
}

// writeFileAtomic keeps readers from ever seeing a partial file. It preserves
// an existing file's mode and creates new ones 0644.
func writeFileAtomic(p string, data []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(p); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), tempPrefix+path.Base(p)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, writeErr := tmp.Write(data)
	var syncErr error
	if writeErr == nil {
		syncErr = tmp.Sync()
	}
	closeErr := tmp.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpName)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// Without the directory fsync a power loss can reorder the journal and
	// config renames the crash-recovery contract depends on.
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
