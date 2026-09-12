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

package checkpoint

import (
	"testing"
)

func TestResourceID(t *testing.T) {
	id := ResourceID{ContainerName: "c1", Path: "/data"}
	if !id.Ok() {
		t.Errorf("ResourceID%+v.Ok() = false, want true", id)
	}
	if got, want := id.String(), "c1:/data"; got != want {
		t.Errorf("ResourceID%+v.String() = %q, want %q", id, got, want)
	}

	zero := ResourceID{}
	if zero.Ok() {
		t.Errorf("ResourceID%+v.Ok() = true, want false", zero)
	}
}
