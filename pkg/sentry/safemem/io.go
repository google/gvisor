// Copyright 2018 Google LLC
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
	"errors"
	"io"
	"math"
)

// ErrEndOfBlockSeq is returned by BlockSeqWriter when attempting to write
// beyond the end of the BlockSeq.
var ErrEndOfBlockSeq = errors.New("write beyond end of BlockSeq")

// Reader represents a streaming byte source like io.Reader.
type Reader interface {
	// ReadToBlocks reads up to dsts.NumBytes() bytes into dsts and returns the
	// number of bytes read. It may return a partial read without an error
	// (i.e. (n, nil) where 0 < n < dsts.NumBytes()). It should not return a
	// full read with an error (i.e. (dsts.NumBytes(), err) where err != nil);
	// note that this differs from io.Reader.Read (in particular, io.EOF should
	// not be returned if ReadToBlocks successfully reads dsts.NumBytes()
	// bytes.)
	ReadToBlocks(dsts BlockSeq) (uint64, error)
}

// Writer represents a streaming byte sink like io.Writer.
type Writer interface {
	// WriteFromBlocks writes up to srcs.NumBytes() bytes from srcs and returns
	// the number of bytes written. It may return a partial write without an
	// error (i.e. (n, nil) where 0 < n < srcs.NumBytes()). It should not
	// return a full write with an error (i.e. srcs.NumBytes(), err) where err
	// != nil).
	WriteFromBlocks(srcs BlockSeq) (uint64, error)
}

// ReadFullToBlocks repeatedly invokes r.ReadToBlocks until dsts.NumBytes()
// bytes have been read or ReadToBlocks returns an error.
func ReadFullToBlocks(r Reader, dsts BlockSeq) (uint64, error) {
	var done uint64
	for !dsts.IsEmpty() {
		n, err := r.ReadToBlocks(dsts)
		done += n
		if err != nil {
			return done, err
		}
		dsts = dsts.DropFirst64(n)
	}
	return done, nil
}

// WriteFullFromBlocks repeatedly invokes w.WriteFromBlocks until
// srcs.NumBytes() bytes have been written or WriteFromBlocks returns an error.
func WriteFullFromBlocks(w Writer, srcs BlockSeq) (uint64, error) {
	var done uint64
	for !srcs.IsEmpty() {
		n, err := w.WriteFromBlocks(srcs)
		done += n
		if err != nil {
			return done, err
		}
		srcs = srcs.DropFirst64(n)
	}
	return done, nil
}

// BlockSeqReader implements Reader by reading from a BlockSeq.
type BlockSeqReader struct {
	Blocks BlockSeq
}

// ReadToBlocks implements Reader.ReadToBlocks.
func (r *BlockSeqReader) ReadToBlocks(dsts BlockSeq) (uint64, error) {
	n, err := CopySeq(dsts, r.Blocks)
	r.Blocks = r.Blocks.DropFirst64(n)
	if err != nil {
		return n, err
	}
	if n < dsts.NumBytes() {
		return n, io.EOF
	}
	return n, nil
}

// BlockSeqWriter implements Writer by writing to a BlockSeq.
type BlockSeqWriter struct {
	Blocks BlockSeq
}

// WriteFromBlocks implements Writer.WriteFromBlocks.
func (w *BlockSeqWriter) WriteFromBlocks(srcs BlockSeq) (uint64, error) {
	n, err := CopySeq(w.Blocks, srcs)
	w.Blocks = w.Blocks.DropFirst64(n)
	if err != nil {
		return n, err
	}
	if n < srcs.NumBytes() {
		return n, ErrEndOfBlockSeq
	}
	return n, nil
}

// ReaderFunc implements Reader for a function with the semantics of
// Reader.ReadToBlocks.
type ReaderFunc func(dsts BlockSeq) (uint64, error)

// ReadToBlocks implements Reader.ReadToBlocks.
func (f ReaderFunc) ReadToBlocks(dsts BlockSeq) (uint64, error) {
	return f(dsts)
}

// WriterFunc implements Writer for a function with the semantics of
// Writer.WriteFromBlocks.
type WriterFunc func(srcs BlockSeq) (uint64, error)

// WriteFromBlocks implements Writer.WriteFromBlocks.
func (f WriterFunc) WriteFromBlocks(srcs BlockSeq) (uint64, error) {
	return f(srcs)
}

// ToIOReader implements io.Reader for a (safemem.)Reader.
//
// ToIOReader will return a successful partial read iff Reader.ReadToBlocks does
// so.
type ToIOReader struct {
	Reader Reader
}

// Read implements io.Reader.Read.
func (r ToIOReader) Read(dst []byte) (int, error) {
	n, err := r.Reader.ReadToBlocks(BlockSeqOf(BlockFromSafeSlice(dst)))
	return int(n), err
}

// ToIOWriter implements io.Writer for a (safemem.)Writer.
type ToIOWriter struct {
	Writer Writer
}

// Write implements io.Writer.Write.
func (w ToIOWriter) Write(src []byte) (int, error) {
	// io.Writer does not permit partial writes.
	n, err := WriteFullFromBlocks(w.Writer, BlockSeqOf(BlockFromSafeSlice(src)))
	return int(n), err
}

// FromIOReader implements Reader for an io.Reader by repeatedly invoking
// io.Reader.Read until it returns an error or partial read.
//
// FromIOReader will return a successful partial read iff Reader.Read does so.
type FromIOReader struct {
	Reader io.Reader
}

// ReadToBlocks implements Reader.ReadToBlocks.
func (r FromIOReader) ReadToBlocks(dsts BlockSeq) (uint64, error) {
	var buf []byte
	var done uint64
	for !dsts.IsEmpty() {
		dst := dsts.Head()
		var n int
		var err error
		n, buf, err = r.readToBlock(dst, buf)
		done += uint64(n)
		if n != dst.Len() {
			return done, err
		}
		dsts = dsts.Tail()
		if err != nil {
			if dsts.IsEmpty() && err == io.EOF {
				return done, nil
			}
			return done, err
		}
	}
	return done, nil
}

func (r FromIOReader) readToBlock(dst Block, buf []byte) (int, []byte, error) {
	// io.Reader isn't safecopy-aware, so we have to buffer Blocks that require
	// safecopy.
	if !dst.NeedSafecopy() {
		n, err := r.Reader.Read(dst.ToSlice())
		return n, buf, err
	}
	if len(buf) < dst.Len() {
		buf = make([]byte, dst.Len())
	}
	rn, rerr := r.Reader.Read(buf[:dst.Len()])
	wbn, wberr := Copy(dst, BlockFromSafeSlice(buf[:rn]))
	if wberr != nil {
		return wbn, buf, wberr
	}
	return wbn, buf, rerr
}

// FromIOWriter implements Writer for an io.Writer by repeatedly invoking
// io.Writer.Write until it returns an error or partial write.
//
// FromIOWriter will tolerate implementations of io.Writer.Write that return
// partial writes with a nil error in contravention of io.Writer's
// requirements, since Writer is permitted to do so. FromIOWriter will return a
// successful partial write iff Writer.Write does so.
type FromIOWriter struct {
	Writer io.Writer
}

// WriteFromBlocks implements Writer.WriteFromBlocks.
func (w FromIOWriter) WriteFromBlocks(srcs BlockSeq) (uint64, error) {
	var buf []byte
	var done uint64
	for !srcs.IsEmpty() {
		src := srcs.Head()
		var n int
		var err error
		n, buf, err = w.writeFromBlock(src, buf)
		done += uint64(n)
		if n != src.Len() || err != nil {
			return done, err
		}
		srcs = srcs.Tail()
	}
	return done, nil
}

func (w FromIOWriter) writeFromBlock(src Block, buf []byte) (int, []byte, error) {
	// io.Writer isn't safecopy-aware, so we have to buffer Blocks that require
	// safecopy.
	if !src.NeedSafecopy() {
		n, err := w.Writer.Write(src.ToSlice())
		return n, buf, err
	}
	if len(buf) < src.Len() {
		buf = make([]byte, src.Len())
	}
	bufn, buferr := Copy(BlockFromSafeSlice(buf[:src.Len()]), src)
	wn, werr := w.Writer.Write(buf[:bufn])
	if werr != nil {
		return wn, buf, werr
	}
	return wn, buf, buferr
}

// FromVecReaderFunc implements Reader for a function that reads data into a
// [][]byte and returns the number of bytes read as an int64.
type FromVecReaderFunc struct {
	ReadVec func(dsts [][]byte) (int64, error)
}

// ReadToBlocks implements Reader.ReadToBlocks.
//
// ReadToBlocks calls r.ReadVec at most once.
func (r FromVecReaderFunc) ReadToBlocks(dsts BlockSeq) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}
	// Ensure that we don't pass a [][]byte with a total length > MaxInt64.
	dsts = dsts.TakeFirst64(uint64(math.MaxInt64))
	dstSlices := make([][]byte, 0, dsts.NumBlocks())
	// Buffer Blocks that require safecopy.
	for tmp := dsts; !tmp.IsEmpty(); tmp = tmp.Tail() {
		dst := tmp.Head()
		if dst.NeedSafecopy() {
			dstSlices = append(dstSlices, make([]byte, dst.Len()))
		} else {
			dstSlices = append(dstSlices, dst.ToSlice())
		}
	}
	rn, rerr := r.ReadVec(dstSlices)
	dsts = dsts.TakeFirst64(uint64(rn))
	var done uint64
	var i int
	for !dsts.IsEmpty() {
		dst := dsts.Head()
		if dst.NeedSafecopy() {
			n, err := Copy(dst, BlockFromSafeSlice(dstSlices[i]))
			done += uint64(n)
			if err != nil {
				return done, err
			}
		} else {
			done += uint64(dst.Len())
		}
		dsts = dsts.Tail()
		i++
	}
	return done, rerr
}

// FromVecWriterFunc implements Writer for a function that writes data from a
// [][]byte and returns the number of bytes written.
type FromVecWriterFunc struct {
	WriteVec func(srcs [][]byte) (int64, error)
}

// WriteFromBlocks implements Writer.WriteFromBlocks.
//
// WriteFromBlocks calls w.WriteVec at most once.
func (w FromVecWriterFunc) WriteFromBlocks(srcs BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}
	// Ensure that we don't pass a [][]byte with a total length > MaxInt64.
	srcs = srcs.TakeFirst64(uint64(math.MaxInt64))
	srcSlices := make([][]byte, 0, srcs.NumBlocks())
	// Buffer Blocks that require safecopy.
	var buferr error
	for tmp := srcs; !tmp.IsEmpty(); tmp = tmp.Tail() {
		src := tmp.Head()
		if src.NeedSafecopy() {
			slice := make([]byte, src.Len())
			n, err := Copy(BlockFromSafeSlice(slice), src)
			srcSlices = append(srcSlices, slice[:n])
			if err != nil {
				buferr = err
				break
			}
		} else {
			srcSlices = append(srcSlices, src.ToSlice())
		}
	}
	n, err := w.WriteVec(srcSlices)
	if err != nil {
		return uint64(n), err
	}
	return uint64(n), buferr
}
