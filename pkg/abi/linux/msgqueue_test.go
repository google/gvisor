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

func TestMsgqueueConstants(t *testing.T) {
	// Verify control commands match Linux include/uapi/linux/msg.h.
	if MSG_STAT != 11 {
		t.Errorf("MSG_STAT = %d, want 11", MSG_STAT)
	}
	if MSG_INFO != 12 {
		t.Errorf("MSG_INFO = %d, want 12", MSG_INFO)
	}
	if MSG_STAT_ANY != 13 {
		t.Errorf("MSG_STAT_ANY = %d, want 13", MSG_STAT_ANY)
	}

	// Verify msgrcv(2) options match Linux include/uapi/linux/msg.h.
	if MSG_NOERROR != 010000 {
		t.Errorf("MSG_NOERROR = %#o, want 010000", MSG_NOERROR)
	}
	if MSG_EXCEPT != 020000 {
		t.Errorf("MSG_EXCEPT = %#o, want 020000", MSG_EXCEPT)
	}
	if MSG_COPY != 040000 {
		t.Errorf("MSG_COPY = %#o, want 040000", MSG_COPY)
	}

	// Verify system-wide limits match Linux include/uapi/linux/msg.h.
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
	got := binary.Size(ds)
	if got <= 0 {
		t.Fatalf("binary.Size(MsqidDS{}) = %d, want > 0", got)
	}
}

func TestMsgBufSizeBytes(t *testing.T) {
	tests := []struct {
		name     string
		textLen  int
		wantSize int
	}{
		{
			name:     "empty text",
			textLen:  0,
			wantSize: 8, // Int64 = 8 bytes, empty ByteSlice = 0 bytes.
		},
		{
			name:     "non-empty text",
			textLen:  10,
			wantSize: 18, // Int64 = 8 bytes + 10 bytes text.
		},
		{
			name:     "large text",
			textLen:  MSGMAX,
			wantSize: 8 + MSGMAX,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := MsgBuf{
				Type: primitive.Int64(1),
				Text: primitive.ByteSlice(make([]byte, tc.textLen)),
			}
			if got := buf.SizeBytes(); got != tc.wantSize {
				t.Errorf("MsgBuf.SizeBytes() = %d, want %d", got, tc.wantSize)
			}
		})
	}
}

func TestMsgBufMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		msgType  int64
		text     []byte
	}{
		{
			name:    "empty message",
			msgType: 1,
			text:    []byte{},
		},
		{
			name:    "simple message",
			msgType: 42,
			text:    []byte("hello"),
		},
		{
			name:    "negative type",
			msgType: -1,
			text:    []byte("test"),
		},
		{
			name:    "max type value",
			msgType: 1<<63 - 1,
			text:    []byte{0xff, 0xfe, 0xfd},
		},
		{
			name:    "zero type",
			msgType: 0,
			text:    []byte("zero"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := MsgBuf{
				Type: primitive.Int64(tc.msgType),
				Text: primitive.ByteSlice(tc.text),
			}

			size := original.SizeBytes()
			buf := make([]byte, size)
			remaining := original.MarshalBytes(buf)
			if len(remaining) != 0 {
				t.Errorf("MarshalBytes returned %d remaining bytes, want 0", len(remaining))
			}

			restored := MsgBuf{
				Text: primitive.ByteSlice(make([]byte, len(tc.text))),
			}
			remaining = restored.UnmarshalBytes(buf)
			if len(remaining) != 0 {
				t.Errorf("UnmarshalBytes returned %d remaining bytes, want 0", len(remaining))
			}

			if int64(restored.Type) != tc.msgType {
				t.Errorf("Type = %d, want %d", int64(restored.Type), tc.msgType)
			}
			if !bytes.Equal([]byte(restored.Text), tc.text) {
				t.Errorf("Text = %v, want %v", []byte(restored.Text), tc.text)
			}
		})
	}
}

func TestMsgBufMarshalRoundTrip(t *testing.T) {
	original := MsgBuf{
		Type: primitive.Int64(7),
		Text: primitive.ByteSlice([]byte("round trip")),
	}

	size := original.SizeBytes()
	buf := make([]byte, size)
	original.MarshalBytes(buf)

	// Marshal again and verify deterministic output.
	buf2 := make([]byte, size)
	original.MarshalBytes(buf2)
	if !bytes.Equal(buf, buf2) {
		t.Error("MarshalBytes is not deterministic")
	}
}

func TestMsgInfoSize(t *testing.T) {
	var info MsgInfo
	got := binary.Size(info)
	if got <= 0 {
		t.Fatalf("binary.Size(MsgInfo{}) = %d, want > 0", got)
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
