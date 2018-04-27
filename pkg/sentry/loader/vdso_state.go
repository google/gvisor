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

package loader

import (
	"debug/elf"
)

type elfProgHeader struct {
	Type   elf.ProgType
	Flags  elf.ProgFlag
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// savePhdrs is invoked by stateify.
func (v *VDSO) savePhdrs() []elfProgHeader {
	s := make([]elfProgHeader, 0, len(v.phdrs))
	for _, h := range v.phdrs {
		s = append(s, elfProgHeader(h))
	}
	return s
}

// loadPhdrs is invoked by stateify.
func (v *VDSO) loadPhdrs(s []elfProgHeader) {
	v.phdrs = make([]elf.ProgHeader, 0, len(s))
	for _, h := range s {
		v.phdrs = append(v.phdrs, elf.ProgHeader(h))
	}
}
