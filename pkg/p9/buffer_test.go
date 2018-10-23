// Copyright 2018 Google Inc.
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

package p9

import (
	"testing"
)

func TestBufferOverrun(t *testing.T) {
	buf := &buffer{
		// This header indicates that a large string should follow, but
		// it is only two bytes. Reading a string should cause an
		// overrun.
		data: []byte{0x0, 0x16},
	}
	if s := buf.ReadString(); s != "" {
		t.Errorf("overrun read got %s, want empty", s)
	}
}
