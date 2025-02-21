// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runtimeoptions

import (
	"bytes"
	"testing"

	shim "github.com/containerd/containerd/runtime/v1/shim/v1"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/proto"
)

func TestCreateTaskRequest(t *testing.T) {
	// Serialize the top-level message.
	const encodedText = `options: <
  type_url: "runtimeoptions.v1.Options"
  value: "\n\010type_url\022\013config_path"
>`
	got := &shim.CreateTaskRequest{} // Should have raw options.
	if err := proto.UnmarshalText(encodedText, got); err != nil {
		t.Fatalf("unable to unmarshal text: %v", err)
	}
	var textBuffer bytes.Buffer
	if err := proto.MarshalText(&textBuffer, got); err != nil {
		t.Errorf("unable to marshal text: %v", err)
	}
	t.Logf("got: %s", string(textBuffer.Bytes()))

	// Check the options.
	wantOptions := &Options{}
	wantOptions.TypeUrl = "type_url"
	wantOptions.ConfigPath = "config_path"
	gotMessage, err := typeurl.UnmarshalAny(got.Options)
	if err != nil {
		t.Fatalf("unable to unmarshal any: %v", err)
	}
	gotOptions, ok := gotMessage.(*Options)
	if !ok {
		t.Fatalf("got %v, want %v", gotMessage, wantOptions)
	}
	if !proto.Equal(gotOptions, wantOptions) {
		t.Fatalf("got %v, want %v", gotOptions, wantOptions)
	}
}
