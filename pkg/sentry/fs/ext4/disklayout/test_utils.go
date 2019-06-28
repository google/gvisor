// Copyright 2019 The gVisor Authors.
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

package disklayout

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/binary"
)

func assertSize(t *testing.T, v interface{}, want uintptr) {
	t.Helper()

	if got := binary.Size(v); got != want {
		t.Errorf("struct %s should be exactly %d bytes but is %d bytes", reflect.TypeOf(v).Name(), want, got)
	}
}
