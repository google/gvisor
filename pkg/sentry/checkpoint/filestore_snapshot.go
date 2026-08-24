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

package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

// FilestoreSnapshot identifies a private MemoryFile (by ResourceID) and the
// destination host file its backing file is FICLONE'd (reflink-cloned) to
// during a state checkpoint's freeze window. Taking the snapshot inside the
// window makes the filestore snapshot and the saved memory-state metadata
// describe the same instant, which is what allows the combination to remain
// correct with leave-running checkpoints.
//
// It is defined here (rather than in pkg/sentry/state) so that both
// pkg/sentry/kernel and pkg/sentry/state can use it without an import cycle.
type FilestoreSnapshot struct {
	// ID identifies the private MemoryFile to snapshot.
	ID ResourceID
	// Name is the artifact file name the destination will get in the
	// snapshot directory (e.g. "filestore-0"); it is recorded in the
	// filestores.json sidecar manifest.
	Name string
	// Dest is the (pre-created, empty) destination file for the reflink
	// clone. It lives on the same filesystem as the snapshot directory.
	Dest *os.File
}

// FilestoreSidecarEntry is one entry of the filestores.json artifact manifest
// written next to in-window filestore snapshots (`runsc checkpoint
// --filestore-snapshot-dir`) and verified at adoption time (`runsc restore
// --filestore-adopt-dir`). It is defined here so that the writer (the sentry,
// inside the save freeze window) and the verifier (runsc/container, host-side,
// before the sandbox starts) share one schema.
type FilestoreSidecarEntry struct {
	// File is the artifact file name, relative to the snapshot/adopt dir.
	File string `json:"file"`
	// ResourceContainer and ResourcePath identify the mount this artifact
	// backs (ResourceID fields).
	ResourceContainer string `json:"resource_container"`
	ResourcePath      string `json:"resource_path"`
	// SizeBytes is the exact stat size of the artifact.
	SizeBytes uint64 `json:"size_bytes"`
	// ChunkCount is the number of pgalloc chunks in the filestore.
	ChunkCount uint64 `json:"chunk_count"`
	// Fingerprint is the sampled SHA-256 (FingerprintFile) of the artifact.
	Fingerprint string `json:"fingerprint"`
}

// FilestoreSidecar is the top-level filestores.json document.
type FilestoreSidecar struct {
	Filestores []FilestoreSidecarEntry `json:"filestores"`
}

// WriteFilestoreSidecar writes the filestores.json manifest to w.
func WriteFilestoreSidecar(w io.Writer, entries []FilestoreSidecarEntry) error {
	data, err := json.Marshal(FilestoreSidecar{Filestores: entries})
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

// fingerprintChunkSize is the amount of data sampled from each end of a file
// for FilestoreSidecarEntry.Fingerprint.
const fingerprintChunkSize = 4096

// FingerprintFile returns an O(1)-cost sampled fingerprint of file: the hex
// SHA-256 of the first and last fingerprintChunkSize bytes of the file. It is
// used to detect "same size, different contents" mistakes when a host file is
// used as externally-saved MemoryFile content (checkpoint metadata records the
// fingerprint at save time; adoption verifies it).
func FingerprintFile(file *os.File) (string, error) {
	fi, err := file.Stat()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	size := fi.Size()
	var buf [fingerprintChunkSize]byte
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
		if size > fingerprintChunkSize {
			if err := readAt(size - fingerprintChunkSize); err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
