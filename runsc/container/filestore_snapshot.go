// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// filestoresSidecarName is the name of the artifact manifest written by
// `runsc checkpoint --filestore-snapshot-dir` into the snapshot directory.
// Its presence on restore switches adoption from the legacy index-based
// convention to runsc-issued, verified artifact credentials.
const filestoresSidecarName = "filestores.json"

// filestoreSidecarEntry describes one filestore snapshot artifact. It is
// issued by runsc at checkpoint time (inside the save freeze window) and
// verified by runsc at adoption time, making the (checkpoint image,
// filestore artifacts) pairing a runsc-backed contract instead of an
// orchestrator-side convention.
type filestoreSidecarEntry struct {
	// File is the artifact file name, relative to the snapshot/adopt dir.
	File string `json:"file"`
	// ResourceContainer and ResourcePath identify the mount this artifact
	// backs (checkpoint.ResourceID fields).
	ResourceContainer string `json:"resource_container"`
	ResourcePath      string `json:"resource_path"`
	// SizeBytes is the exact stat size of the artifact.
	SizeBytes uint64 `json:"size_bytes"`
	// ChunkCount is the number of pgalloc chunks in the filestore.
	ChunkCount uint64 `json:"chunk_count"`
	// Fingerprint is the sampled SHA-256 (first and last 4KiB) of the artifact.
	Fingerprint string `json:"fingerprint"`
}

type filestoreSidecar struct {
	Filestores []filestoreSidecarEntry `json:"filestores"`
}

// fingerprintFile matches pgalloc's sampled fingerprint (SHA-256 of the first
// and last 4KiB) so that sidecar entries can be verified host-side before the
// sandbox is even started.
func fingerprintFile(file *os.File) (string, error) {
	const fpChunk = 4096
	fi, err := file.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	size := fi.Size()
	var buf [fpChunk]byte
	readAt := func(off int64) error {
		n, err := file.ReadAt(buf[:], off)
		if err != nil && err != io.EOF {
			return err
		}
		h.Write(buf[:n])
		return nil
	}
	if size > 0 {
		if err := readAt(0); err != nil {
			return "", err
		}
		if size > fpChunk {
			if err := readAt(size - fpChunk); err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// filestoreResourceID returns the checkpoint resource ID that identifies the
// filestore backing the mount at destination dest ("/" for the rootfs). It
// mirrors how the sentry names private MemoryFiles (boot/vfs.go
// configureRestore), so that sidecar entries can be matched to mounts by
// identity rather than by position.
//
// NOTE: for specs without an explicit container name, the sentry falls back
// to creation-order names ("__no_name_<n>"); only the first container of a
// sandbox is supported by this helper.
func (c *Container) filestoreResourceID(dest string) checkpoint.ResourceID {
	name := specutils.ContainerName(c.Spec)
	if len(name) == 0 {
		name = "__no_name_0"
	}
	return checkpoint.ResourceID{ContainerName: name, Path: dest}
}

// filestoreAdopter adopts checkpoint-artifact filestores on restore, with
// sidecar verification and clone-on-adopt.
type filestoreAdopter struct {
	dir     string
	clone   bool
	entries map[checkpoint.ResourceID]*filestoreSidecarEntry
	legacy  bool // no sidecar present: use index-based convention
	nextIdx int
}

func newFilestoreAdopter(conf *config.Config, c *Container) (*filestoreAdopter, error) {
	a := &filestoreAdopter{
		dir:   conf.FilestoreAdoptDir,
		clone: conf.FilestoreCloneOnAdopt,
	}
	data, err := os.ReadFile(path.Join(a.dir, filestoresSidecarName))
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read filestore sidecar in %q: %w", a.dir, err)
		}
		// No sidecar: artifacts come from an external orchestrator (e.g. a
		// park daemon); fall back to the index-based convention. The
		// pgalloc-level exact-size and fingerprint checks in the checkpoint
		// still apply once the sandbox starts.
		a.legacy = true
		log.Debugf("No filestores.json in adopt dir %q; using legacy index-based adoption", a.dir)
		return a, nil
	}
	var sc filestoreSidecar
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("failed to parse filestore sidecar %q: %w", path.Join(a.dir, filestoresSidecarName), err)
	}
	a.entries = make(map[checkpoint.ResourceID]*filestoreSidecarEntry, len(sc.Filestores))
	for i := range sc.Filestores {
		e := &sc.Filestores[i]
		rid := checkpoint.ResourceID{ContainerName: e.ResourceContainer, Path: e.ResourcePath}
		if _, dup := a.entries[rid]; dup {
			return nil, fmt.Errorf("filestore sidecar in %q has duplicate entry for resource %+v", a.dir, rid)
		}
		a.entries[rid] = e
	}
	return a, nil
}

// adopt opens the filestore artifact for the mount at destination dest. With
// a sidecar, the artifact is selected and verified by resource identity
// (exact size + sampled fingerprint); without, by legacy index. With
// clone-on-adopt, a reflink private copy is adopted instead of the artifact
// itself, keeping the artifact an immutable template.
func (a *filestoreAdopter) adopt(c *Container, dest string) (*os.File, error) {
	var (
		artifactPath string
		expSize      uint64
		expFP        string
	)
	if a.legacy {
		artifactPath = path.Join(a.dir, fmt.Sprintf("filestore-%d", a.nextIdx))
		a.nextIdx++
	} else {
		rid := c.filestoreResourceID(dest)
		e := a.entries[rid]
		if e == nil {
			return nil, fmt.Errorf("filestore sidecar in %q has no artifact for mount %q (resource %+v); the checkpoint and the adopt directory do not match", a.dir, dest, rid)
		}
		artifactPath = path.Join(a.dir, e.File)
		expSize, expFP = e.SizeBytes, e.Fingerprint
	}
	if !path.IsAbs(a.dir) {
		return nil, fmt.Errorf("filestore adopt directory %q must be an absolute path", a.dir)
	}
	fileInfo, err := os.Stat(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat filestore artifact %q: %w", artifactPath, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("filestore artifact %q is not a regular file", artifactPath)
	}
	if fileInfo.Size() == 0 {
		return nil, fmt.Errorf("filestore artifact %q is empty; it must contain the adopted writable-layer contents", artifactPath)
	}
	if !a.legacy {
		// Sidecar credentials: exact size + sampled fingerprint, checked
		// before the sandbox is started so a swapped or diverged artifact
		// fails fast with the offending artifact named.
		if uint64(fileInfo.Size()) != expSize {
			return nil, fmt.Errorf("filestore artifact %q has size %d, sidecar records %d; artifact and sidecar do not match", artifactPath, fileInfo.Size(), expSize)
		}
		if expFP != "" {
			if err := func() error {
				f, err := os.Open(artifactPath)
				if err != nil {
					return err
				}
				defer f.Close()
				fp, err := fingerprintFile(f)
				if err != nil {
					return err
				}
				if fp != expFP {
					return fmt.Errorf("fingerprint mismatch: got %s, sidecar records %s; artifact contents differ from what was checkpointed", fp[:16], expFP[:16])
				}
				return nil
			}(); err != nil {
				return nil, fmt.Errorf("failed to verify filestore artifact %q against sidecar: %w", artifactPath, err)
			}
		}
	}
	src, err := os.OpenFile(artifactPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open filestore artifact %q: %w", artifactPath, err)
	}
	if !a.clone {
		// Consuming adoption: the restored sandbox mutates the artifact
		// in place (legacy unpark semantics, and the only option on
		// filesystems without reflink).
		log.Debugf("Adopting filestore file at %q (consuming)", artifactPath)
		return src, nil
	}
	// Clone-on-adopt: reflink a private CoW copy in the same directory (same
	// filesystem), unlinked immediately so it is anonymous exactly like a
	// freshly created filestore. The artifact itself is never truncated or
	// mutated (pgalloc's LoadFrom truncate lands on the copy), so it stays a
	// reusable read-only template and multiple restores from one directory
	// cannot share writable state.
	clone, err := os.CreateTemp(a.dir, "runsc-filestore-adopt-")
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("failed to create clone for filestore artifact %q: %w", artifactPath, err)
	}
	cloneName := clone.Name()
	ok := false
	defer func() {
		if !ok {
			clone.Close()
			os.Remove(cloneName)
		}
	}()
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, clone.Fd(), unix.FICLONE, src.Fd()); errno != 0 {
		return nil, fmt.Errorf("--filestore-clone-on-adopt: FICLONE of %q failed (%w); the filesystem may not support reflink (e.g. ext4) — use --filestore-clone-on-adopt=false for a consuming restore", artifactPath, errno)
	}
	if err := unix.Unlink(cloneName); err != nil {
		return nil, fmt.Errorf("failed to unlink filestore clone %q: %w", cloneName, err)
	}
	src.Close()
	ok = true
	log.Debugf("Adopting reflink clone of filestore file at %q", artifactPath)
	return clone, nil
}

// prepareFilestoreSnapshot creates the snapshot artifact files for
// `runsc checkpoint --filestore-snapshot-dir` and records the
// (resource ID → destination FD) targets that the sentry will FICLONE into
// inside the checkpoint's freeze window. The sidecar temp file is appended
// last; it is renamed to filestores.json by the caller on success.
func (c *Container) prepareFilestoreSnapshot(snapDir string) (targets []checkpoint.ResourceID, destFiles []*os.File, sidecar *os.File, err error) {
	if !path.IsAbs(snapDir) {
		return nil, nil, nil, fmt.Errorf("--filestore-snapshot-dir %q must be an absolute path", snapDir)
	}
	_, statErr := os.Stat(snapDir)
	createdDir := os.IsNotExist(statErr)
	if err := os.MkdirAll(snapDir, 0700); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create filestore snapshot directory %q: %w", snapDir, err)
	}
	cleanup := func(cause error) ([]checkpoint.ResourceID, []*os.File, *os.File, error) {
		for _, f := range destFiles {
			f.Close()
			os.Remove(f.Name())
		}
		if sidecar != nil {
			sidecar.Close()
			os.Remove(sidecar.Name())
		}
		if createdDir {
			// Don't leave behind an empty directory we created if the
			// checkpoint is rejected (e.g. self-overlay mounts).
			os.Remove(snapDir)
		}
		return nil, nil, nil, cause
	}
	// Enumerate filestore mounts in the same order as createGoferFilestores
	// (root first, then spec mount order). Self-overlay filestores are a
	// named file inside the mount source, not an anonymous artifact; they
	// can be neither snapshotted as an artifact nor adopted, so reject at
	// checkpoint time (mirroring the restore-side guard) instead of
	// producing a snapshot directory that can never be restored.
	dests := []string{"/"}
	if rootfsConf := c.GoferMountConfs[0]; !rootfsConf.IsFilestorePresent() {
		dests = nil
	} else if rootfsConf.IsSelfBacked() {
		return cleanup(fmt.Errorf("--filestore-snapshot-dir supports anonymous filestores only (overlay2 'dir=' medium); the root mount uses the self overlay medium and its named filestore cannot be snapshotted for adoption"))
	}
	mountIdx := 1 // first one is the root
	for _, m := range c.Spec.Mounts {
		if !specutils.HasMountConfig(m) {
			continue
		}
		if c.GoferMountConfs[mountIdx].IsFilestorePresent() {
			if c.GoferMountConfs[mountIdx].IsSelfBacked() {
				return cleanup(fmt.Errorf("--filestore-snapshot-dir supports anonymous filestores only (overlay2 'dir=' medium); mount %q uses the self overlay medium and its named filestore cannot be snapshotted for adoption", m.Destination))
			}
			dests = append(dests, m.Destination)
		}
		mountIdx++
	}
	for i, dest := range dests {
		name := path.Join(snapDir, "filestore-"+strconv.Itoa(i))
		f, err := os.OpenFile(name, os.O_RDWR|unix.O_CREAT|os.O_EXCL|unix.O_CLOEXEC, 0600)
		if err != nil {
			return cleanup(fmt.Errorf("failed to create filestore snapshot artifact %q (use a fresh --filestore-snapshot-dir for each checkpoint): %w", name, err))
		}
		destFiles = append(destFiles, f)
		targets = append(targets, c.filestoreResourceID(dest))
	}
	sc, err := os.OpenFile(path.Join(snapDir, filestoresSidecarName+".tmp"), os.O_WRONLY|unix.O_CREAT|os.O_EXCL|unix.O_CLOEXEC, 0600)
	if err != nil {
		return cleanup(fmt.Errorf("failed to create filestore sidecar temp file in %q: %w", snapDir, err))
	}
	return targets, destFiles, sc, nil
}
