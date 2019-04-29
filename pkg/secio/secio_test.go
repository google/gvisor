// Copyright 2018 The gVisor Authors.
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

package secio

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"math"
	"testing"
)

var errEndOfBuffer = errors.New("write beyond end of buffer")

// buffer resembles bytes.Buffer, but implements io.ReaderAt and io.WriterAt.
// Reads beyond the end of the buffer return io.EOF. Writes beyond the end of
// the buffer return errEndOfBuffer.
type buffer struct {
	Bytes []byte
}

// ReadAt implements io.ReaderAt.ReadAt.
func (b *buffer) ReadAt(dst []byte, off int64) (int, error) {
	if off >= int64(len(b.Bytes)) {
		return 0, io.EOF
	}
	n := copy(dst, b.Bytes[off:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

// WriteAt implements io.WriterAt.WriteAt.
func (b *buffer) WriteAt(src []byte, off int64) (int, error) {
	if off >= int64(len(b.Bytes)) {
		return 0, errEndOfBuffer
	}
	n := copy(b.Bytes[off:], src)
	if n < len(src) {
		return n, errEndOfBuffer
	}
	return n, nil
}

func newBufferString(s string) *buffer {
	return &buffer{[]byte(s)}
}

func TestOffsetReader(t *testing.T) {
	buf := newBufferString("foobar")
	r := NewOffsetReader(buf, 3)
	dst, err := ioutil.ReadAll(r)
	if want := []byte("bar"); !bytes.Equal(dst, want) || err != nil {
		t.Errorf("ReadAll: got (%q, %v), wanted (%q, nil)", dst, err, want)
	}
}

func TestSectionReader(t *testing.T) {
	buf := newBufferString("foobarbaz")
	r := NewSectionReader(buf, 3, 3)
	dst, err := ioutil.ReadAll(r)
	if want, wantErr := []byte("bar"), ErrReachedLimit; !bytes.Equal(dst, want) || err != wantErr {
		t.Errorf("ReadAll: got (%q, %v), wanted (%q, %v)", dst, err, want, wantErr)
	}
}

func TestSectionReaderLimitOverflow(t *testing.T) {
	// SectionReader behaves like OffsetReader when limit overflows int64.
	buf := newBufferString("foobar")
	r := NewSectionReader(buf, 3, math.MaxInt64)
	dst, err := ioutil.ReadAll(r)
	if want := []byte("bar"); !bytes.Equal(dst, want) || err != nil {
		t.Errorf("ReadAll: got (%q, %v), wanted (%q, nil)", dst, err, want)
	}
}

func TestOffsetWriter(t *testing.T) {
	buf := newBufferString("ABCDEF")
	w := NewOffsetWriter(buf, 3)
	n, err := w.Write([]byte("foobar"))
	if wantN, wantErr := 3, errEndOfBuffer; n != wantN || err != wantErr {
		t.Errorf("WriteAt: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := buf.Bytes, []byte("ABCfoo"); !bytes.Equal(got, want) {
		t.Errorf("buf.Bytes: got %q, wanted %q", got, want)
	}
}

func TestSectionWriter(t *testing.T) {
	buf := newBufferString("ABCDEFGHI")
	w := NewSectionWriter(buf, 3, 3)
	n, err := w.Write([]byte("foobar"))
	if wantN, wantErr := 3, ErrReachedLimit; n != wantN || err != wantErr {
		t.Errorf("WriteAt: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := buf.Bytes, []byte("ABCfooGHI"); !bytes.Equal(got, want) {
		t.Errorf("buf.Bytes: got %q, wanted %q", got, want)
	}
}

func TestSectionWriterLimitOverflow(t *testing.T) {
	// SectionWriter behaves like OffsetWriter when limit overflows int64.
	buf := newBufferString("ABCDEF")
	w := NewSectionWriter(buf, 3, math.MaxInt64)
	n, err := w.Write([]byte("foobar"))
	if wantN, wantErr := 3, errEndOfBuffer; n != wantN || err != wantErr {
		t.Errorf("WriteAt: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := buf.Bytes, []byte("ABCfoo"); !bytes.Equal(got, want) {
		t.Errorf("buf.Bytes: got %q, wanted %q", got, want)
	}
}
