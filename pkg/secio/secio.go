// Copyright 2018 Google Inc.
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

// Package secio provides support for sectioned I/O.
package secio

import (
	"errors"
	"io"
)

// ErrReachedLimit is returned when SectionReader.Read or SectionWriter.Write
// reaches its limit.
var ErrReachedLimit = errors.New("reached limit")

// SectionReader implements io.Reader on a section of an underlying io.ReaderAt.
// It is similar to io.SectionReader, but:
//
// - Reading beyond the limit returns ErrReachedLimit, not io.EOF.
//
// - Limit overflow is handled correctly.
type SectionReader struct {
	r     io.ReaderAt
	off   int64
	limit int64
}

// Read implements io.Reader.Read.
func (r *SectionReader) Read(dst []byte) (int, error) {
	if r.limit >= 0 {
		if max := r.limit - r.off; max < int64(len(dst)) {
			dst = dst[:max]
		}
	}
	n, err := r.r.ReadAt(dst, r.off)
	r.off += int64(n)
	if err == nil && r.off == r.limit {
		err = ErrReachedLimit
	}
	return n, err
}

// NewOffsetReader returns an io.Reader that reads from r starting at offset
// off.
func NewOffsetReader(r io.ReaderAt, off int64) *SectionReader {
	return &SectionReader{r, off, -1}
}

// NewSectionReader returns an io.Reader that reads from r starting at offset
// off and stops with ErrReachedLimit after n bytes.
func NewSectionReader(r io.ReaderAt, off int64, n int64) *SectionReader {
	// If off + n overflows, it will be < 0 such that no limit applies, but
	// this is the correct behavior as long as r prohibits reading at offsets
	// beyond MaxInt64.
	return &SectionReader{r, off, off + n}
}

// SectionWriter implements io.Writer on a section of an underlying
// io.WriterAt. Writing beyond the limit returns ErrReachedLimit.
type SectionWriter struct {
	w     io.WriterAt
	off   int64
	limit int64
}

// Write implements io.Writer.Write.
func (w *SectionWriter) Write(src []byte) (int, error) {
	if w.limit >= 0 {
		if max := w.limit - w.off; max < int64(len(src)) {
			src = src[:max]
		}
	}
	n, err := w.w.WriteAt(src, w.off)
	w.off += int64(n)
	if err == nil && w.off == w.limit {
		err = ErrReachedLimit
	}
	return n, err
}

// NewOffsetWriter returns an io.Writer that writes to w starting at offset
// off.
func NewOffsetWriter(w io.WriterAt, off int64) *SectionWriter {
	return &SectionWriter{w, off, -1}
}

// NewSectionWriter returns an io.Writer that writes to w starting at offset
// off and stops with ErrReachedLimit after n bytes.
func NewSectionWriter(w io.WriterAt, off int64, n int64) *SectionWriter {
	// If off + n overflows, it will be < 0 such that no limit applies, but
	// this is the correct behavior as long as w prohibits writing at offsets
	// beyond MaxInt64.
	return &SectionWriter{w, off, off + n}
}
