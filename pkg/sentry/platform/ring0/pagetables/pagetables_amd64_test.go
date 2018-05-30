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

// +build amd64

package pagetables

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

func Test2MAnd4K(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map a small page and a huge page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)
	pt.Map(0x00007f0000000000, pmdSize, MapOpts{AccessType: usermem.Read}, pmdSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.ReadWrite}},
		{0x00007f0000000000, pmdSize, pmdSize * 47, MapOpts{AccessType: usermem.Read}},
	})
	pt.Release()
}

func Test1GAnd4K(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map a small page and a super page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: usermem.ReadWrite}, pteSize*42)
	pt.Map(0x00007f0000000000, pudSize, MapOpts{AccessType: usermem.Read}, pudSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: usermem.ReadWrite}},
		{0x00007f0000000000, pudSize, pudSize * 47, MapOpts{AccessType: usermem.Read}},
	})
	pt.Release()
}

func TestSplit1GPage(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map a super page and knock out the middle.
	pt.Map(0x00007f0000000000, pudSize, MapOpts{AccessType: usermem.Read}, pudSize*42)
	pt.Unmap(usermem.Addr(0x00007f0000000000+pteSize), pudSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{0x00007f0000000000, pteSize, pudSize * 42, MapOpts{AccessType: usermem.Read}},
		{0x00007f0000000000 + pudSize - pteSize, pteSize, pudSize*42 + pudSize - pteSize, MapOpts{AccessType: usermem.Read}},
	})
	pt.Release()
}

func TestSplit2MPage(t *testing.T) {
	pt := New(reflectTranslater{}, Opts{})

	// Map a huge page and knock out the middle.
	pt.Map(0x00007f0000000000, pmdSize, MapOpts{AccessType: usermem.Read}, pmdSize*42)
	pt.Unmap(usermem.Addr(0x00007f0000000000+pteSize), pmdSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{0x00007f0000000000, pteSize, pmdSize * 42, MapOpts{AccessType: usermem.Read}},
		{0x00007f0000000000 + pmdSize - pteSize, pteSize, pmdSize*42 + pmdSize - pteSize, MapOpts{AccessType: usermem.Read}},
	})
	pt.Release()
}
