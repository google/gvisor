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

package linux

import (
	"testing"
)

// TestMsgBufMarshalUnmarshal tests the marshaling and unmarshaling of the MsgBuf struct.
func TestMsgBufMarshalUnmarshal(t *testing.T) {
	// Create a sample MsgBuf instance to test.
	msg := MsgBuf{
		Type: primitive.Int64(42),
		Text: primitive.ByteSlice([]byte("Hello, world!")),
	}

	// Marshal the MsgBuf to bytes.
	marshaled := msg.MarshalBytes(nil)

	// Create a new MsgBuf and unmarshal the bytes into it.
	var unmarshaled MsgBuf
	if err := unmarshaled.UnmarshalBytes(marshaled); err != nil {
		t.Fatalf("UnmarshalBytes failed: %v", err)
	}

	// Check if the unmarshaled MsgBuf matches the original.
	if unmarshaled.Type != msg.Type || string(unmarshaled.Text) != string(msg.Text) {
		t.Errorf("Unmarshaled MsgBuf does not match the original.")
	}
}

// TestMsgInfoMarshalUnmarshal tests the marshaling and unmarshaling of the MsgInfo struct.
func TestMsgInfoMarshalUnmarshal(t *testing.T) {
	// Create a sample MsgInfo instance to test.
	info := MsgInfo{
		MsgPool: 100,
		MsgMap:  200,
		MsgMax:  300,
		MsgMnb:  400,
		MsgMni:  500,
		MsgSsz:  600,
		MsgTql:  700,
		MsgSeg:  800,
	}

	// Marshal the MsgInfo to bytes.
	marshaled := info.MarshalBytes(nil)

	// Create a new MsgInfo and unmarshal the bytes into it.
	var unmarshaled MsgInfo
	if err := unmarshaled.UnmarshalBytes(marshaled); err != nil {
		t.Fatalf("UnmarshalBytes failed: %v", err)
	}

	// Check if the unmarshaled MsgInfo matches the original.
	if unmarshaled != info {
		t.Errorf("Unmarshaled MsgInfo does not match the original.")
	}
}
