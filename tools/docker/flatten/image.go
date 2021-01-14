// Copyright 2021 The gVisor Authors.
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

package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type readSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

// TarImage implements oci.Image for a multi-level tar created by `docker
// save`.
//
// TarImage is not thread-safe.
type TarImage struct {
	// source is the underlying tar source.
	//
	// We don't hold a tar.Reader here because we always read from the
	// beginning, as we want to do "random" access without reading
	// everything into memory.
	source readSeekCloser
}

// NewTarImage returns a TarImage for path.
func NewTarImage(path string) (*TarImage, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening tar: %v", err)
	}

	return &TarImage{
		source: f,
	}, nil
}

// Close closes the image.
func (t *TarImage) Close() {
	t.source.Close()
}

// reader returns a new tar.Reader starting at the beginning of the archive. It
// should not be used acrossed multiple exported methods.
func (t *TarImage) reader() *tar.Reader {
	if _, err := t.source.Seek(0, io.SeekStart); err != nil {
		panic(fmt.Sprintf("failed to seek to start: %v", err))
	}
	return tar.NewReader(t.source)
}

// findFile returns the header and seeked reader for file name. Returns io.EOF
// if file does not exist.
func (t *TarImage) findFile(name string) (*tar.Header, *tar.Reader, error) {
	r := t.reader()
	for {
		h, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		if h.Name == name {
			return h, r, nil
		}
	}
}

// manifest is the format of the image manifest.json, described at
// https://github.com/moby/moby/blob/4fb59c20a4fb54f944fe170d0ff1d00eb4a24d6f/image/spec/v1.2.md#combined-image-json--filesystem-changeset-format.
type manifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// readManifest extracts the manifest from the image.
func (t *TarImage) readManifest() (*manifest, error) {
	_, r, err := t.findFile("manifest.json")
	if err != nil {
		return nil, fmt.Errorf("error finding manifest.json: %v", err)
	}

	// The manifest file is actually an array of manifests (to support
	// parent images). We only support a single entry.
	var m []manifest
	d := json.NewDecoder(r)
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("error decoding manifest.json: %v", err)
	}

	if len(m) != 1 {
		return nil, fmt.Errorf("unable to handle more than 1 manifest: %+v", m)
	}

	return &m[0], nil
}
