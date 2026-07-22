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
	"archive/tar"
	"compress/bzip2"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/runsc/gvisorbinaries"
	"gvisor.dev/gvisor/runsc/version"
)

// sidecarPolicy controls when a sidecar-related action applies.
// It implements flag.Value.
type sidecarPolicy string

// Valid sidecarPolicy values.
const (
	sidecarNever          sidecarPolicy = "NEVER"
	sidecarAlways         sidecarPolicy = "ALWAYS"
	sidecarIfReleaseBuild sidecarPolicy = "IF_RELEASE_BUILD"
)

// String implements flag.Value.String.
func (p *sidecarPolicy) String() string {
	return string(*p)
}

// Set implements flag.Value.Set.
func (p *sidecarPolicy) Set(s string) error {
	v := sidecarPolicy(strings.ToUpper(s))
	switch v {
	case sidecarNever, sidecarAlways, sidecarIfReleaseBuild:
		*p = v
		return nil
	}
	return fmt.Errorf("invalid value %q; must be %s, %s, or %s", s, sidecarNever, sidecarAlways, sidecarIfReleaseBuild)
}

// applies returns whether the policy is in effect for this runsc build.
func (p sidecarPolicy) applies() bool {
	return p == sidecarAlways || (p == sidecarIfReleaseBuild && isReleaseBuild())
}

// releaseVersionRE matches the version string of tagged release builds.
var releaseVersionRE = regexp.MustCompile(`^release-(\d{8}(?:\.\d+)?)$`)

// isReleaseBuild returns whether this runsc's version is a tagged release.
func isReleaseBuild() bool {
	return releaseVersionRE.MatchString(version.Version())
}

// releaseArches maps GOARCH to the architecture names used in release URLs.
var releaseArches = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

func releaseTarballURL(ver, goarch string) (string, error) {
	m := releaseVersionRE.FindStringSubmatch(ver)
	if m == nil {
		return "", fmt.Errorf("cannot map version %q to a release download URL; please download sidecar binaries manually", ver)
	}
	arch, ok := releaseArches[goarch]
	if !ok {
		return "", fmt.Errorf("unknown architecture %q", goarch)
	}
	return fmt.Sprintf("https://storage.googleapis.com/gvisor/releases/release/%s/%s/gvisor.tar.bz2", m[1], arch), nil
}

// fetch downloads url to dest using curl or wget, whichever exists.
// We do this because we cannot link net/http in `runsc`.
func fetch(url, dest string) error {
	var cmd *exec.Cmd
	if curl, err := exec.LookPath("curl"); err == nil {
		cmd = exec.Command(curl, "-fsSL", "-o", dest, url)
	} else if wget, err := exec.LookPath("wget"); err == nil {
		cmd = exec.Command(wget, "-q", "-O", dest, url)
	} else {
		return errors.New("cannot download sidecar binaries: neither curl nor wget found in $PATH")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cannot download (%s): %w: %s", strings.Join(cmd.Args, " "), err, out)
	}
	return nil
}

// verifySHA512 checks a file against the sha512 checksum file.
func verifySHA512(file, sumFile string) error {
	sum, err := os.ReadFile(sumFile)
	if err != nil {
		return fmt.Errorf("cannot read checksum file: %w", err)
	}
	fields := strings.Fields(string(sum))
	if len(fields) == 0 {
		return fmt.Errorf("checksum file %q is empty", sumFile)
	}
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open tarball: %w", err)
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("cannot hash tarball: %w", err)
	}
	if got, want := hex.EncodeToString(h.Sum(nil)), fields[0]; !strings.EqualFold(got, want) {
		return fmt.Errorf("SHA-512 mismatch for %q: got %s, expected %s", file, got, want)
	}
	return nil
}

// extractSidecars extracts `gvisor-bin/`.
func extractSidecars(tarball, dir string) error {
	parent := filepath.Dir(dir)
	tmpDir := filepath.Join(parent, ".gvisor-bin.tmp")
	oldDir := filepath.Join(parent, ".gvisor-bin.old")
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("cannot remove stale directory: %w", err)
	}
	if err := os.RemoveAll(oldDir); err != nil {
		return fmt.Errorf("cannot remove stale directory: %w", err)
	}
	if err := os.Mkdir(tmpDir, 0755); err != nil {
		return fmt.Errorf("cannot create extraction directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	f, err := os.Open(tarball)
	if err != nil {
		return fmt.Errorf("cannot open tarball: %w", err)
	}
	defer f.Close()
	tr := tar.NewReader(bzip2.NewReader(f))
	extracted := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading %q: %w", tarball, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := strings.CutPrefix(strings.TrimPrefix(path.Clean(hdr.Name), "/"), "gvisor-bin/")
		if !ok || name == "" || strings.Contains(name, "/") {
			continue
		}
		dst, err := os.OpenFile(filepath.Join(tmpDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if err != nil {
			return fmt.Errorf("extracting %q: %w", hdr.Name, err)
		}
		_, err = io.Copy(dst, tr)
		if closeErr := dst.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return fmt.Errorf("extracting %q: %w", hdr.Name, err)
		}
		extracted++
	}
	if extracted == 0 {
		return fmt.Errorf("%q contains no gvisor-bin/ members", tarball)
	}
	// Swap the new directory into place.
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, oldDir); err != nil {
			return fmt.Errorf("cannot move old sidecar directory aside: %w", err)
		}
	}
	if err := os.Rename(tmpDir, dir); err != nil {
		return fmt.Errorf("cannot move new sidecar directory into place: %w", err)
	}
	if err := os.RemoveAll(oldDir); err != nil {
		return fmt.Errorf("cannot remove old sidecar directory: %w", err)
	}
	return nil
}

// installSidecars ensures that all sidecar binaries are present.
func (i *Install) installSidecars() error {
	var missing []string
	for _, b := range gvisorbinaries.All {
		if _, err := b.Path(); err != nil {
			missing = append(missing, b.Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	dir, err := gvisorbinaries.Dir()
	if err != nil {
		return err
	}
	if !i.DownloadSidecars.applies() {
		return fmt.Errorf("sidecar binaries %v missing (expected under %q); not downloading them (--download-sidecars=%s, release build: %t)", missing, dir, i.DownloadSidecars, isReleaseBuild())
	}
	url := i.SidecarURL
	if url == "" {
		if url, err = releaseTarballURL(version.Version(), runtime.GOARCH); err != nil {
			return fmt.Errorf("missing sidecar binaries %v (expected under %q): %v", missing, dir, err)
		}
	}
	// Download next to the final location to be on the same filesystem.
	parent := filepath.Dir(dir)
	stale, _ := filepath.Glob(filepath.Join(parent, ".runsc-sidecars.*"))
	for _, d := range stale {
		os.RemoveAll(d)
	}
	tmp, err := os.MkdirTemp(parent, ".runsc-sidecars.*")
	if err != nil {
		return fmt.Errorf("cannot create download directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	tarball := filepath.Join(tmp, "gvisor.tar.bz2")
	if err := fetch(url, tarball); err != nil {
		return err
	}
	sumFile := tarball + ".sha512"
	if err := fetch(url+".sha512", sumFile); err != nil {
		return err
	}
	if err := verifySHA512(tarball, sumFile); err != nil {
		return err
	}
	if err := extractSidecars(tarball, dir); err != nil {
		return err
	}
	log.Printf("Installed sidecar binaries from %s to %q. This is BEST-EFFORT FUNCTIONALITY which will STOP WORKING in a few weeks. Please see the gvisor-users mailing list.", url, dir)
	return nil
}
