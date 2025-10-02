// Copyright 2025 The gVisor Authors.
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

package stateio

import (
	"bufio"
	"errors"
	"io"
)

// BufioReadCloser is a wrapper around bufio.Reader that implements io.Closer
// by closing the underlying io.ReadCloser.
type BufioReadCloser struct {
	bufio.Reader
	io.Closer
}

// NewBufioReadCloser returns a new BufioReadCloser whose buffer has the
// default size.
func NewBufioReadCloser(rc io.ReadCloser) *BufioReadCloser {
	brc := &BufioReadCloser{
		Closer: rc,
	}
	brc.Reader.Reset(rc)
	return brc
}

// BufioWriteCloser is a wrapper around bufio.Writer that implements io.Closer
// by closing the underlying io.WriteCloser.
type BufioWriteCloser struct {
	bufio.Writer
	Closer io.Closer
}

// NewBufioWriteCloser returns a new BufioWriteCloser whose buffer has the
// default size.
func NewBufioWriteCloser(wc io.WriteCloser) *BufioWriteCloser {
	bwc := &BufioWriteCloser{
		Closer: wc,
	}
	bwc.Writer.Reset(wc)
	return bwc
}

// Close implements io.Closer.Close.
func (bwc *BufioWriteCloser) Close() error {
	return errors.Join(bwc.Writer.Flush(), bwc.Closer.Close())
}
