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

package linux

import (
	"encoding/binary"
	"testing"
)

func TestSizes(t *testing.T) {
	testCases := []struct {
		typ     any
		defined uintptr
	}{
		{IPTEntry{}, SizeOfIPTEntry},
		{IPTGetEntries{}, SizeOfIPTGetEntries},
		{IPTGetinfo{}, SizeOfIPTGetinfo},
		{IPTIP{}, SizeOfIPTIP},
		{IPTOwnerInfo{}, SizeOfIPTOwnerInfo},
		{IPTReplace{}, SizeOfIPTReplace},
		{XTCounters{}, SizeOfXTCounters},
		{XTEntryMatch{}, SizeOfXTEntryMatch},
		{XTEntryTarget{}, SizeOfXTEntryTarget},
		{XTErrorTarget{}, SizeOfXTErrorTarget},
		{XTStandardTarget{}, SizeOfXTStandardTarget},
		{IP6TReplace{}, SizeOfIP6TReplace},
		{IP6TEntry{}, SizeOfIP6TEntry},
		{IP6TIP{}, SizeOfIP6TIP},
	}

	for _, tc := range testCases {
		if calculated := uintptr(binary.Size(tc.typ)); calculated != tc.defined {
			t.Errorf("%T has a defined size of %d and calculated size of %d", tc.typ, tc.defined, calculated)
		}
	}
}
