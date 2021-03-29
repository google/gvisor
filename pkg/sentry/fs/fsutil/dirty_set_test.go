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

package fsutil

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

func TestDirtySet(t *testing.T) {
	var set DirtySet
	set.MarkDirty(memmap.MappableRange{0, 2 * hostarch.PageSize})
	set.KeepDirty(memmap.MappableRange{hostarch.PageSize, 2 * hostarch.PageSize})
	set.MarkClean(memmap.MappableRange{0, 2 * hostarch.PageSize})
	want := &DirtySegmentDataSlices{
		Start:  []uint64{hostarch.PageSize},
		End:    []uint64{2 * hostarch.PageSize},
		Values: []DirtyInfo{{Keep: true}},
	}
	if got := set.ExportSortedSlices(); !reflect.DeepEqual(got, want) {
		t.Errorf("set:\n\tgot %v,\n\twant %v", got, want)
	}
}
