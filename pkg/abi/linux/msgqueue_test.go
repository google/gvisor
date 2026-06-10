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

package linux

import (
	"bytes"
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// TestMsgqueueConstants validates that the Linux constants have the expected
// values. These values are taken from include/uapi/linux/msg.h and must stay in
// sync with the kernel headers.
func TestMsgqueueConstants(t *testing.T) {
	if MSG_STAT != 11 {
		t.Errorf("MSG_STAT = %d, want 11", MSG_STAT)
	}
	if MSG_INFO != 12 {
		t.Errorf("MSG_INFO = %d, want 12", MSG_INFO)
	}
	if MSG_STAT_ANY != 13 {
		t.Errorf("MSG_STAT_ANY = %d, want 13", MSG_STAT_ANY)
	}
	if MSG_NOERROR != 010000 {
		t.Errorf("MSG_NOERROR = %#o, want 010000", MSG_NOERROR)
	}
	if MSG_EXCEPT != 020000 {
		t.Errorf("MSG_EXCEPT = %#o, want 020000", MSG_EXCEPT)
	}
	if MSG_COPY != 040000 {
		t.Errorf("MSG_COPY = %#o, want 040000", MSG_COPY)
	}
	if MSGMNI != 32000 {
		t.Errorf("MSGMNI = %d, want 32000", MSGMNI)
	}
	if MSGMAX != 8192 {
		t.Errorf("MSGMAX = %d, want 8192", MSGMAX)
	}
	if MSGMNB != 16384 {
		t.Errorf("MSGMNB = %d, want 16384", MSGMNB)
	}
}

// TestMsgqueueDerivedConstants checks constants that are calculated from the
// base values.
func TestMsgqueueDerivedConstants(t *testing.T) {
	if MSGPOOL != (MSGMNI * MSGMNB / 1024) {
		t.Errorf("MSGPOOL = %d, want %d", MSGPOOL, MSGMNI*MSGMNB/1024)
	}
	if MSGTQL != MSGMNB {
		t.Errorf("MSGTQL = %d, want %d", MSGTQL, MSGMNB)
	}
	if MSGMAP != MSGMNB {
		t.Errorf("MSGMAP = %d, want %d", MSGMAP, MSGMNB)
	}
	if MSGSSZ != 16 {
		t.Errorf("MSGSSZ = %d, want 16", MSGSSZ)
	}
	if MSGSEG != 0xffff {
		t.Errorf("MSGSEG = %#x, want 0xffff", MSGSEG)
	}
}

func TestMsqidDSSize(t *testing.T) {
	var ds MsqidDS
	if sz := binary.Size(ds); sz <= 0 {
		t.Fatalf("binary.Size(MsqidDS{}) = %d, want >0", sz)
	}
}

func TestMsgInfoSize(t *testing.T) {
	var info MsgInfo
	if sz := binary.Size(info); sz <= 0 {
		t.Fatalf("binary.Size(MsgInfo{}) = %d, want >0", sz)
	}
}

func TestMsgInfoFields(t *testing.T) {
	info := MsgInfo{
		MsgPool: int32(MSGPOOL),
		MsgMap:  int32(MSGMAP),
		MsgMax:  MSGMAX,
		MsgMnb:  MSGMNB,
		MsgMni:  MSGMNI,
		MsgSsz:  MSGSSZ,
		MsgTql:  int32(MSGTQL),
		MsgSeg:  MSGSEG,
	}
	if info.MsgMax != 8192 {
		t.Errorf("MsgInfo.MsgMax = %d, want 8192", info.MsgMax)
	}
	if info.MsgMnb != 16384 {
		t.Errorf("MsgInfo.MsgMnb = %d, want 16384", info.MsgMnb)
	}
	if info.MsgMni != 32000 {
		t.Errorf("MsgInfo.MsgMni = %d, want 32000", info.MsgMni)
	}
	if info.MsgSsz != 16 {
		t.Errorf("MsgInfo.MsgSsz = %d, want 16", info.MsgSsz)
	}
	if info.MsgSeg != 0xffff {
		t.Errorf("MsgInfo.MsgSeg = %#x, want 0xffff", info.MsgSeg)
	}
}

// TestMsgBufSizeBytes exercises SizeBytes for a few representative lengths.
func TestMsgBufSizeBytes(t *testing.T) {
	cases := []struct {
		name    string
		textLen int
		want    int
	}{
		{"empty", 0, 8},             // Int64 = 8, no text.
		{"short", 10, 18},           // 8 + 10.
		{"max", MSGMAX, 8 + MSGMAX}, // 8 + MSGMAX.
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := MsgBuf{Type: primitive.Int64(1), Text: primitive.ByteSlice(make([]byte, c.textLen))}
			if got := buf.SizeBytes(); got != c.want {
				t.Errorf("SizeBytes() = %d, want %d", got, c.want)
			}
		})
	}
}

// TestMsgBufMarshalRoundTrip verifies that MarshalBytes followed by
// UnmarshalBytes yields an equivalent MsgBuf.
func TestMsgBufMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		typ  int64
		text []byte
	}{
		{"empty", 1, []byte{}},
		{"simple", 42, []byte("hello")},
		{"negative", -1, []byte("test")},
		{"large", 1<<63 - 1, bytes.Repeat([]byte{'x'}, 1024)},
		{"zero", 0, []byte("zero")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := MsgBuf{Type: primitive.Int64(tc.typ), Text: primitive.ByteSlice(tc.text)}
			dst := make([]byte, orig.SizeBytes())
			// MarshalBytes expects a slice with enough capacity; passing the full slice works.
			remaining := orig.MarshalBytes(dst)
			if len(remaining) != 0 {
				t.Fatalf("MarshalBytes left %d bytes, want 0", len(remaining))
			}
			var out MsgBuf
			out.Text = primitive.ByteSlice(make([]byte, len(tc.text)))
			remaining = out.UnmarshalBytes(dst)
			if len(remaining) != 0 {
				t.Fatalf("UnmarshalBytes left %d bytes, want 0", len(remaining))
			}
			if int64(out.Type) != tc.typ {
				t.Errorf("Type = %d, want %d", int64(out.Type), tc.typ)
			}
			if !bytes.Equal([]byte(out.Text), tc.text) {
				t.Errorf("Text mismatch: got %v, want %v", []byte(out.Text), tc.text)
			}
		})
	}
}

func TestMsgBufMarshalDeterministic(t *testing.T) {
	orig := MsgBuf{Type: primitive.Int64(7), Text: primitive.ByteSlice([]byte("roundtrip"))}
	buf1 := make([]byte, orig.SizeBytes())
	orig.MarshalBytes(buf1)
	buf2 := make([]byte, orig.SizeBytes())
	orig.MarshalBytes(buf2)
	if !bytes.Equal(buf1, buf2) {
		t.Errorf("MarshalBytes is not deterministic")
	}
}
