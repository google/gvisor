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

package usermem

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// newContext returns a context.Context that we can use in these tests (we
// can't use contexttest because it depends on usermem).
func newContext() context.Context {
	return context.Background()
}

func newBytesIOString(s string) *BytesIO {
	return &BytesIO{[]byte(s)}
}

func TestBytesIOCopyOutSuccess(t *testing.T) {
	b := newBytesIOString("ABCDE")
	n, err := b.CopyOut(newContext(), 1, []byte("foo"), IOOpts{})
	if wantN := 3; n != wantN || err != nil {
		t.Errorf("CopyOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := b.Bytes, []byte("AfooE"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyOutFailure(t *testing.T) {
	b := newBytesIOString("ABC")
	n, err := b.CopyOut(newContext(), 1, []byte("foo"), IOOpts{})
	if wantN, wantErr := 2, syserror.EFAULT; n != wantN || err != wantErr {
		t.Errorf("CopyOut: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := b.Bytes, []byte("Afo"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyInSuccess(t *testing.T) {
	b := newBytesIOString("AfooE")
	var dst [3]byte
	n, err := b.CopyIn(newContext(), 1, dst[:], IOOpts{})
	if wantN := 3; n != wantN || err != nil {
		t.Errorf("CopyIn: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst[:], []byte("foo"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyInFailure(t *testing.T) {
	b := newBytesIOString("Afo")
	var dst [3]byte
	n, err := b.CopyIn(newContext(), 1, dst[:], IOOpts{})
	if wantN, wantErr := 2, syserror.EFAULT; n != wantN || err != wantErr {
		t.Errorf("CopyIn: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := dst[:], []byte("fo\x00"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
}

func TestBytesIOZeroOutSuccess(t *testing.T) {
	b := newBytesIOString("ABCD")
	n, err := b.ZeroOut(newContext(), 1, 2, IOOpts{})
	if wantN := int64(2); n != wantN || err != nil {
		t.Errorf("ZeroOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := b.Bytes, []byte("A\x00\x00D"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOZeroOutFailure(t *testing.T) {
	b := newBytesIOString("ABC")
	n, err := b.ZeroOut(newContext(), 1, 3, IOOpts{})
	if wantN, wantErr := int64(2), syserror.EFAULT; n != wantN || err != wantErr {
		t.Errorf("ZeroOut: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := b.Bytes, []byte("A\x00\x00"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyOutFromSuccess(t *testing.T) {
	b := newBytesIOString("ABCDEFGH")
	n, err := b.CopyOutFrom(newContext(), hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 4, End: 7},
		{Start: 1, End: 4},
	}), safemem.FromIOReader{bytes.NewBufferString("barfoo")}, IOOpts{})
	if wantN := int64(6); n != wantN || err != nil {
		t.Errorf("CopyOutFrom: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := b.Bytes, []byte("AfoobarH"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyOutFromFailure(t *testing.T) {
	b := newBytesIOString("ABCDE")
	n, err := b.CopyOutFrom(newContext(), hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 1, End: 4},
		{Start: 4, End: 7},
	}), safemem.FromIOReader{bytes.NewBufferString("foobar")}, IOOpts{})
	if wantN, wantErr := int64(4), syserror.EFAULT; n != wantN || err != wantErr {
		t.Errorf("CopyOutFrom: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := b.Bytes, []byte("Afoob"); !bytes.Equal(got, want) {
		t.Errorf("Bytes: got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyInToSuccess(t *testing.T) {
	b := newBytesIOString("AfoobarH")
	var dst bytes.Buffer
	n, err := b.CopyInTo(newContext(), hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 4, End: 7},
		{Start: 1, End: 4},
	}), safemem.FromIOWriter{&dst}, IOOpts{})
	if wantN := int64(6); n != wantN || err != nil {
		t.Errorf("CopyInTo: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst.Bytes(), []byte("barfoo"); !bytes.Equal(got, want) {
		t.Errorf("dst.Bytes(): got %q, wanted %q", got, want)
	}
}

func TestBytesIOCopyInToFailure(t *testing.T) {
	b := newBytesIOString("Afoob")
	var dst bytes.Buffer
	n, err := b.CopyInTo(newContext(), hostarch.AddrRangeSeqFromSlice([]hostarch.AddrRange{
		{Start: 1, End: 4},
		{Start: 4, End: 7},
	}), safemem.FromIOWriter{&dst}, IOOpts{})
	if wantN, wantErr := int64(4), syserror.EFAULT; n != wantN || err != wantErr {
		t.Errorf("CopyOutFrom: got (%v, %v), wanted (%v, %v)", n, err, wantN, wantErr)
	}
	if got, want := dst.Bytes(), []byte("foob"); !bytes.Equal(got, want) {
		t.Errorf("dst.Bytes(): got %q, wanted %q", got, want)
	}
}

type testStruct struct {
	Int8   int8
	Uint8  uint8
	Int16  int16
	Uint16 uint16
	Int32  int32
	Uint32 uint32
	Int64  int64
	Uint64 uint64
}

func TestCopyStringInShort(t *testing.T) {
	// Tests for string length <= copyStringIncrement.
	want := strings.Repeat("A", copyStringIncrement-2)
	mem := want + "\x00"
	if got, err := CopyStringIn(newContext(), newBytesIOString(mem), 0, 2*copyStringIncrement, IOOpts{}); got != want || err != nil {
		t.Errorf("CopyStringIn: got (%q, %v), wanted (%q, nil)", got, err, want)
	}
}

func TestCopyStringInLong(t *testing.T) {
	// Tests for copyStringIncrement < string length <= copyStringMaxInitBufLen
	// (requiring multiple calls to IO.CopyIn()).
	want := strings.Repeat("A", copyStringIncrement*3/4) + strings.Repeat("B", copyStringIncrement*3/4)
	mem := want + "\x00"
	if got, err := CopyStringIn(newContext(), newBytesIOString(mem), 0, 2*copyStringIncrement, IOOpts{}); got != want || err != nil {
		t.Errorf("CopyStringIn: got (%q, %v), wanted (%q, nil)", got, err, want)
	}
}

func TestCopyStringInVeryLong(t *testing.T) {
	// Tests for string length > copyStringMaxInitBufLen (requiring buffer
	// reallocation).
	want := strings.Repeat("A", copyStringMaxInitBufLen*3/4) + strings.Repeat("B", copyStringMaxInitBufLen*3/4)
	mem := want + "\x00"
	if got, err := CopyStringIn(newContext(), newBytesIOString(mem), 0, 2*copyStringMaxInitBufLen, IOOpts{}); got != want || err != nil {
		t.Errorf("CopyStringIn: got (%q, %v), wanted (%q, nil)", got, err, want)
	}
}

func TestCopyStringInNoTerminatingZeroByte(t *testing.T) {
	want := strings.Repeat("A", copyStringIncrement-1)
	got, err := CopyStringIn(newContext(), newBytesIOString(want), 0, 2*copyStringIncrement, IOOpts{})
	if wantErr := syserror.EFAULT; got != want || err != wantErr {
		t.Errorf("CopyStringIn: got (%q, %v), wanted (%q, %v)", got, err, want, wantErr)
	}
}

func TestCopyStringInTruncatedByMaxlen(t *testing.T) {
	got, err := CopyStringIn(newContext(), newBytesIOString(strings.Repeat("A", 10)), 0, 5, IOOpts{})
	if want, wantErr := strings.Repeat("A", 5), linuxerr.ENAMETOOLONG; got != want || err != wantErr {
		t.Errorf("CopyStringIn: got (%q, %v), wanted (%q, %v)", got, err, want, wantErr)
	}
}

func TestCopyInt32StringsInVec(t *testing.T) {
	for _, test := range []struct {
		str     string
		n       int
		initial []int32
		final   []int32
	}{
		{
			str:     "100 200",
			n:       len("100 200"),
			initial: []int32{1, 2},
			final:   []int32{100, 200},
		},
		{
			// Fewer values ok
			str:     "100",
			n:       len("100"),
			initial: []int32{1, 2},
			final:   []int32{100, 2},
		},
		{
			// Extra values ok
			str:     "100 200 300",
			n:       len("100 200 "),
			initial: []int32{1, 2},
			final:   []int32{100, 200},
		},
		{
			// Leading and trailing whitespace ok
			str:     " 100\t200\n",
			n:       len(" 100\t200\n"),
			initial: []int32{1, 2},
			final:   []int32{100, 200},
		},
	} {
		t.Run(fmt.Sprintf("%q", test.str), func(t *testing.T) {
			src := BytesIOSequence([]byte(test.str))
			dsts := append([]int32(nil), test.initial...)
			if n, err := CopyInt32StringsInVec(newContext(), src.IO, src.Addrs, dsts, src.Opts); n != int64(test.n) || err != nil {
				t.Errorf("CopyInt32StringsInVec: got (%d, %v), wanted (%d, nil)", n, err, test.n)
			}
			if !reflect.DeepEqual(dsts, test.final) {
				t.Errorf("dsts: got %v, wanted %v", dsts, test.final)
			}
		})
	}
}

func TestCopyInt32StringsInVecRequiresOneValidValue(t *testing.T) {
	for _, s := range []string{"", "\n", "a123"} {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			src := BytesIOSequence([]byte(s))
			initial := []int32{1, 2}
			dsts := append([]int32(nil), initial...)
			if n, err := CopyInt32StringsInVec(newContext(), src.IO, src.Addrs, dsts, src.Opts); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("CopyInt32StringsInVec: got (%d, %v), wanted (_, %v)", n, err, linuxerr.EINVAL)
			}
			if !reflect.DeepEqual(dsts, initial) {
				t.Errorf("dsts: got %v, wanted %v", dsts, initial)
			}
		})
	}
}

func TestIOSequenceCopyOut(t *testing.T) {
	buf := []byte("ABCD")
	s := BytesIOSequence(buf)

	// CopyOut limited by len(src).
	n, err := s.CopyOut(newContext(), []byte("fo"))
	if wantN := 2; n != wantN || err != nil {
		t.Errorf("CopyOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("foCD"); !bytes.Equal(buf, want) {
		t.Errorf("buf: got %q, wanted %q", buf, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(2); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	// CopyOut limited by s.NumBytes().
	n, err = s.CopyOut(newContext(), []byte("obar"))
	if wantN := 2; n != wantN || err != nil {
		t.Errorf("CopyOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("foob"); !bytes.Equal(buf, want) {
		t.Errorf("buf: got %q, wanted %q", buf, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(0); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}
}

func TestIOSequenceCopyIn(t *testing.T) {
	s := BytesIOSequence([]byte("foob"))
	dst := []byte("ABCDEF")

	// CopyIn limited by len(dst).
	n, err := s.CopyIn(newContext(), dst[:2])
	if wantN := 2; n != wantN || err != nil {
		t.Errorf("CopyIn: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("foCDEF"); !bytes.Equal(dst, want) {
		t.Errorf("dst: got %q, wanted %q", dst, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(2); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	// CopyIn limited by s.Remaining().
	n, err = s.CopyIn(newContext(), dst[2:])
	if wantN := 2; n != wantN || err != nil {
		t.Errorf("CopyIn: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("foobEF"); !bytes.Equal(dst, want) {
		t.Errorf("dst: got %q, wanted %q", dst, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(0); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}
}

func TestIOSequenceZeroOut(t *testing.T) {
	buf := []byte("ABCD")
	s := BytesIOSequence(buf)

	// ZeroOut limited by toZero.
	n, err := s.ZeroOut(newContext(), 2)
	if wantN := int64(2); n != wantN || err != nil {
		t.Errorf("ZeroOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("\x00\x00CD"); !bytes.Equal(buf, want) {
		t.Errorf("buf: got %q, wanted %q", buf, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(2); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	// ZeroOut limited by s.NumBytes().
	n, err = s.ZeroOut(newContext(), 4)
	if wantN := int64(2); n != wantN || err != nil {
		t.Errorf("CopyOut: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if want := []byte("\x00\x00\x00\x00"); !bytes.Equal(buf, want) {
		t.Errorf("buf: got %q, wanted %q", buf, want)
	}
	s = s.DropFirst(2)
	if got, want := s.NumBytes(), int64(0); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}
}

func TestIOSequenceTakeFirst(t *testing.T) {
	s := BytesIOSequence([]byte("foobar"))
	if got, want := s.NumBytes(), int64(6); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	s = s.TakeFirst(3)
	if got, want := s.NumBytes(), int64(3); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	// TakeFirst(n) where n > s.NumBytes() is a no-op.
	s = s.TakeFirst(9)
	if got, want := s.NumBytes(), int64(3); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}

	var dst [3]byte
	n, err := s.CopyIn(newContext(), dst[:])
	if wantN := 3; n != wantN || err != nil {
		t.Errorf("CopyIn: got (%v, %v), wanted (%v, nil)", n, err, wantN)
	}
	if got, want := dst[:], []byte("foo"); !bytes.Equal(got, want) {
		t.Errorf("dst: got %q, wanted %q", got, want)
	}
	s = s.DropFirst(3)
	if got, want := s.NumBytes(), int64(0); got != want {
		t.Errorf("NumBytes: got %v, wanted %v", got, want)
	}
}
