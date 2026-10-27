// Copyright 2026 The gVisor Authors.
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

package rdmaproxy

import (
	"errors"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

// TestUverbsDeviceIsUnsavable checks that an RDMA device rejects
// checkpointing with a classified error identifying the device. The VFS
// device registry is saved with the kernel, so the rejection must fire even
// when no RDMA file descriptors are open.
func TestUverbsDeviceIsUnsavable(t *testing.T) {
	dev := &uverbsDevice{devName: "uverbs0"}
	if _, err := state.Save(t.Context(), io.Discard, dev); !errors.Is(err, state.ErrUnsavable) {
		t.Fatalf("state.Save = %v, want errors.Is(err, state.ErrUnsavable)", err)
	} else if got := err.Error(); !strings.Contains(got, dev.devName) {
		t.Errorf("state.Save error = %q, want device name %q", got, dev.devName)
	}
}
