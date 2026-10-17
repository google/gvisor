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

// Package zip wraps archive/zip so internal builds can substitute a hardened
// implementation without rewriting its consumers' imports.
package zip

import (
	"archive/zip"
	"io"
)

// File is an alias for zip.File.
type File = zip.File

// ReadCloser is an alias for zip.ReadCloser.
type ReadCloser = zip.ReadCloser

// NewReader returns a new Reader reading from r, which is assumed to have the
// given size in bytes.
func NewReader(r io.ReaderAt, size int64) (*zip.Reader, error) {
	return zip.NewReader(r, size)
}

// NewWriter returns a new Writer writing a ZIP file to w.
func NewWriter(w io.Writer) *zip.Writer {
	return zip.NewWriter(w)
}

// OpenReader opens the ZIP file specified by name and returns a ReadCloser.
func OpenReader(name string) (*ReadCloser, error) {
	return zip.OpenReader(name)
}
