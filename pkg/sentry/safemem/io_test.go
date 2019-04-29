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

package safemem

import (
	"bytes"
	"io"
	"testing"
)

func makeBlocks(slices ...[]byte) []Block {
	blocks := make([]Block, 0, len(slices))
	for _, s := range slices {
		blocks = append(blocks, BlockFromSafeSlice(s))
	}
	return blocks
}

func TestFromIOReaderFullRead(t *testing.T) {
	r := FromIOReader{bytes.NewBufferString("foobar")}
	dsts := makeBlocks(make([]byte, 3), make([]byte, 3))
	n, err := r.ReadToBlocks(BlockSeqFromSlice(dsts))
	if wantN := uint64(6); n != wantN || err != nil {
		t.Errorf("ReadToBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	for i, want := range [][]byte{[]byte("foo"), []byte("bar")} {
		if got := dsts[i].ToSlice(); !bytes.Equal(got, want) {
			t.Errorf("dsts[%d]: got %q, wanted %q", i, got, want)
		}
	}
}

type eofHidingReader struct {
	Reader io.Reader
}

func (r eofHidingReader) Read(dst []byte) (int, error) {
	n, err := r.Reader.Read(dst)
	if err == io.EOF {
		return n, nil
	}
	return n, err
}

func TestFromIOReaderPartialRead(t *testing.T) {
	r := FromIOReader{eofHidingReader{bytes.NewBufferString("foob")}}
	dsts := makeBlocks(make([]byte, 3), make([]byte, 3))
	n, err := r.ReadToBlocks(BlockSeqFromSlice(dsts))
	// FromIOReader should stop after the eofHidingReader returns (1, nil)
	// for a 3-byte read.
	if wantN := uint64(4); n != wantN || err != nil {
		t.Errorf("ReadToBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	for i, want := range [][]byte{[]byte("foo"), []byte("b\x00\x00")} {
		if got := dsts[i].ToSlice(); !bytes.Equal(got, want) {
			t.Errorf("dsts[%d]: got %q, wanted %q", i, got, want)
		}
	}
}

type singleByteReader struct {
	Reader io.Reader
}

func (r singleByteReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return r.Reader.Read(dst)
	}
	return r.Reader.Read(dst[:1])
}

func TestSingleByteReader(t *testing.T) {
	r := FromIOReader{singleByteReader{bytes.NewBufferString("foobar")}}
	dsts := makeBlocks(make([]byte, 3), make([]byte, 3))
	n, err := r.ReadToBlocks(BlockSeqFromSlice(dsts))
	// FromIOReader should stop after the singleByteReader returns (1, nil)
	// for a 3-byte read.
	if wantN := uint64(1); n != wantN || err != nil {
		t.Errorf("ReadToBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	for i, want := range [][]byte{[]byte("f\x00\x00"), []byte("\x00\x00\x00")} {
		if got := dsts[i].ToSlice(); !bytes.Equal(got, want) {
			t.Errorf("dsts[%d]: got %q, wanted %q", i, got, want)
		}
	}
}

func TestReadFullToBlocks(t *testing.T) {
	r := FromIOReader{singleByteReader{bytes.NewBufferString("foobar")}}
	dsts := makeBlocks(make([]byte, 3), make([]byte, 3))
	n, err := ReadFullToBlocks(r, BlockSeqFromSlice(dsts))
	// ReadFullToBlocks should call into FromIOReader => singleByteReader
	// repeatedly until dsts is exhausted.
	if wantN := uint64(6); n != wantN || err != nil {
		t.Errorf("ReadFullToBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	for i, want := range [][]byte{[]byte("foo"), []byte("bar")} {
		if got := dsts[i].ToSlice(); !bytes.Equal(got, want) {
			t.Errorf("dsts[%d]: got %q, wanted %q", i, got, want)
		}
	}
}

func TestFromIOWriterFullWrite(t *testing.T) {
	srcs := makeBlocks([]byte("foo"), []byte("bar"))
	var dst bytes.Buffer
	w := FromIOWriter{&dst}
	n, err := w.WriteFromBlocks(BlockSeqFromSlice(srcs))
	if wantN := uint64(6); n != wantN || err != nil {
		t.Errorf("WriteFromBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst.Bytes(), []byte("foobar"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}

type limitedWriter struct {
	Writer io.Writer
	Done   int
	Limit  int
}

func (w *limitedWriter) Write(src []byte) (int, error) {
	count := len(src)
	if count > (w.Limit - w.Done) {
		count = w.Limit - w.Done
	}
	n, err := w.Writer.Write(src[:count])
	w.Done += n
	return n, err
}

func TestFromIOWriterPartialWrite(t *testing.T) {
	srcs := makeBlocks([]byte("foo"), []byte("bar"))
	var dst bytes.Buffer
	w := FromIOWriter{&limitedWriter{&dst, 0, 4}}
	n, err := w.WriteFromBlocks(BlockSeqFromSlice(srcs))
	// FromIOWriter should stop after the limitedWriter returns (1, nil) for a
	// 3-byte write.
	if wantN := uint64(4); n != wantN || err != nil {
		t.Errorf("WriteFromBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst.Bytes(), []byte("foob"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}

type singleByteWriter struct {
	Writer io.Writer
}

func (w singleByteWriter) Write(src []byte) (int, error) {
	if len(src) == 0 {
		return w.Writer.Write(src)
	}
	return w.Writer.Write(src[:1])
}

func TestSingleByteWriter(t *testing.T) {
	srcs := makeBlocks([]byte("foo"), []byte("bar"))
	var dst bytes.Buffer
	w := FromIOWriter{singleByteWriter{&dst}}
	n, err := w.WriteFromBlocks(BlockSeqFromSlice(srcs))
	// FromIOWriter should stop after the singleByteWriter returns (1, nil)
	// for a 3-byte write.
	if wantN := uint64(1); n != wantN || err != nil {
		t.Errorf("WriteFromBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst.Bytes(), []byte("f"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}

func TestWriteFullToBlocks(t *testing.T) {
	srcs := makeBlocks([]byte("foo"), []byte("bar"))
	var dst bytes.Buffer
	w := FromIOWriter{singleByteWriter{&dst}}
	n, err := WriteFullFromBlocks(w, BlockSeqFromSlice(srcs))
	// WriteFullToBlocks should call into FromIOWriter => singleByteWriter
	// repeatedly until srcs is exhausted.
	if wantN := uint64(6); n != wantN || err != nil {
		t.Errorf("WriteFullFromBlocks: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst.Bytes(), []byte("foobar"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}
