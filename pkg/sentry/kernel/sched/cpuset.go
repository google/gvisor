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

package sched

import "math/bits"

const (
	bitsPerByte  = 8
	bytesPerLong = 8 // only for 64-bit architectures
)

// CPUSet contains a bitmap to record CPU information.
//
// Note that this definition is only correct for little-endian architectures,
// since Linux's cpumask_t uses unsigned long.
type CPUSet []byte

// CPUSetSize returns the size in bytes of a CPUSet that can contain num cpus.
func CPUSetSize(num uint) uint {
	// NOTE: Applications may expect that the size of a CPUSet in
	// bytes is always a multiple of sizeof(unsigned long), since this is true
	// in Linux. Thus we always round up.
	bytes := (num + bitsPerByte - 1) / bitsPerByte
	longs := (bytes + bytesPerLong - 1) / bytesPerLong
	return longs * bytesPerLong
}

// NewCPUSet returns a CPUSet for the given number of CPUs which initially
// contains no CPUs.
func NewCPUSet(num uint) CPUSet {
	return CPUSet(make([]byte, CPUSetSize(num)))
}

// NewFullCPUSet returns a CPUSet for the given number of CPUs, all of which
// are present in the set.
func NewFullCPUSet(num uint) CPUSet {
	c := NewCPUSet(num)
	var i uint
	for ; i < num/bitsPerByte; i++ {
		c[i] = 0xff
	}
	if rem := num % bitsPerByte; rem != 0 {
		c[i] = (1 << rem) - 1
	}
	return c
}

// Size returns the size of 'c' in bytes.
func (c CPUSet) Size() uint {
	return uint(len(c))
}

// NumCPUs returns how many cpus are set in the CPUSet.
func (c CPUSet) NumCPUs() uint {
	var n int
	for _, b := range c {
		n += bits.OnesCount8(b)
	}
	return uint(n)
}

// Copy returns a copy of the CPUSet.
func (c CPUSet) Copy() CPUSet {
	return append(CPUSet(nil), c...)
}

// Set sets the bit corresponding to cpu.
func (c *CPUSet) Set(cpu uint) {
	(*c)[cpu/bitsPerByte] |= 1 << (cpu % bitsPerByte)
}

// ClearAbove clears bits corresponding to cpu and all higher cpus.
func (c *CPUSet) ClearAbove(cpu uint) {
	i := cpu / bitsPerByte
	if i >= c.Size() {
		return
	}
	(*c)[i] &^= 0xff << (cpu % bitsPerByte)
	for i++; i < c.Size(); i++ {
		(*c)[i] = 0
	}
}

// ForEachCPU iterates over the CPUSet and calls fn with the cpu index if
// it's set.
func (c CPUSet) ForEachCPU(fn func(uint)) {
	for i := uint(0); i < c.Size()*bitsPerByte; i++ {
		bit := uint(1) << (i & (bitsPerByte - 1))
		if uint(c[i/bitsPerByte])&bit == bit {
			fn(i)
		}
	}
}
