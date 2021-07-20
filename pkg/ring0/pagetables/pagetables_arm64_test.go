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

//go:build arm64
// +build arm64

package pagetables

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func Test2MAnd4K(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a small page and a huge page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize*42)
	pt.Map(0x0000ff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize*47)

	pt.Map(0xffff000000400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite, User: false}, pteSize*42)
	pt.Map(0xffffff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: false}, pmdSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pmdSize, pmdSize * 47, MapOpts{AccessType: hostarch.Read, User: true}},
		{0xffff000000400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite, User: false}},
		{0xffffff0000000000, pmdSize, pmdSize * 47, MapOpts{AccessType: hostarch.Read, User: false}},
	})
}

func Test1GAnd4K(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a small page and a super page.
	pt.Map(0x400000, pteSize, MapOpts{AccessType: hostarch.ReadWrite, User: true}, pteSize*42)
	pt.Map(0x0000ff0000000000, pudSize, MapOpts{AccessType: hostarch.Read, User: true}, pudSize*47)

	checkMappings(t, pt, []mapping{
		{0x400000, pteSize, pteSize * 42, MapOpts{AccessType: hostarch.ReadWrite, User: true}},
		{0x0000ff0000000000, pudSize, pudSize * 47, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

func TestSplit1GPage(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a super page and knock out the middle.
	pt.Map(0x0000ff0000000000, pudSize, MapOpts{AccessType: hostarch.Read, User: true}, pudSize*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize), pudSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize, pudSize * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pudSize - pteSize, pteSize, pudSize*42 + pudSize - pteSize, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}

func TestSplit2MPage(t *testing.T) {
	pt := New(NewRuntimeAllocator())

	// Map a huge page and knock out the middle.
	pt.Map(0x0000ff0000000000, pmdSize, MapOpts{AccessType: hostarch.Read, User: true}, pmdSize*42)
	pt.Unmap(hostarch.Addr(0x0000ff0000000000+pteSize), pmdSize-(2*pteSize))

	checkMappings(t, pt, []mapping{
		{0x0000ff0000000000, pteSize, pmdSize * 42, MapOpts{AccessType: hostarch.Read, User: true}},
		{0x0000ff0000000000 + pmdSize - pteSize, pteSize, pmdSize*42 + pmdSize - pteSize, MapOpts{AccessType: hostarch.Read, User: true}},
	})
}
