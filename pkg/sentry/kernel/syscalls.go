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

package kernel

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// maxSyscallNum is the highest supported syscall number.
//
// The types below create fast lookup slices for all syscalls. This maximum
// serves as a sanity check that we don't allocate huge slices for a very large
// syscall. This is checked during registration.
const maxSyscallNum = 2000

// SyscallSupportLevel is a syscall support levels.
type SyscallSupportLevel int

// String returns a human readable represetation of the support level.
func (l SyscallSupportLevel) String() string {
	switch l {
	case SupportUnimplemented:
		return "Unimplemented"
	case SupportPartial:
		return "Partial Support"
	case SupportFull:
		return "Full Support"
	default:
		return "Undocumented"
	}
}

const (
	// SupportUndocumented indicates the syscall is not documented yet.
	SupportUndocumented = iota

	// SupportUnimplemented indicates the syscall is unimplemented.
	SupportUnimplemented

	// SupportPartial indicates the syscall is partially supported.
	SupportPartial

	// SupportFull indicates the syscall is fully supported.
	SupportFull
)

// Syscall includes the syscall implementation and compatibility information.
type Syscall struct {
	// Name is the syscall name.
	Name string
	// Fn is the implementation of the syscall.
	Fn SyscallFn
	// SupportLevel is the level of support implemented in gVisor.
	SupportLevel SyscallSupportLevel
	// Note describes the compatibility of the syscall.
	Note string
	// URLs is set of URLs to any relevant bugs or issues.
	URLs []string
}

// SyscallFn is a syscall implementation.
type SyscallFn func(t *Task, args arch.SyscallArguments) (uintptr, *SyscallControl, error)

// MissingFn is a syscall to be called when an implementation is missing.
type MissingFn func(t *Task, sysno uintptr, args arch.SyscallArguments) (uintptr, error)

// Possible flags for SyscallFlagsTable.enable.
const (
	// syscallPresent indicates that this is not a missing syscall.
	//
	// This flag is used internally in SyscallFlagsTable.
	syscallPresent = 1 << iota

	// StraceEnableLog enables syscall log tracing.
	StraceEnableLog

	// StraceEnableEvent enables syscall event tracing.
	StraceEnableEvent

	// ExternalBeforeEnable enables the external hook before syscall execution.
	ExternalBeforeEnable

	// ExternalAfterEnable enables the external hook after syscall execution.
	ExternalAfterEnable
)

// StraceEnableBits combines both strace log and event flags.
const StraceEnableBits = StraceEnableLog | StraceEnableEvent

// SyscallFlagsTable manages a set of enable/disable bit fields on a per-syscall
// basis.
type SyscallFlagsTable struct {
	// mu protects writes to the fields below.
	//
	// Atomic loads are always allowed. Atomic stores are allowed only
	// while mu is held.
	mu sync.Mutex

	// enable contains the enable bits for each syscall.
	//
	// missing syscalls have the same value in enable as missingEnable to
	// avoid an extra branch in Word.
	enable []uint32

	// missingEnable contains the enable bits for missing syscalls.
	missingEnable uint32
}

// Init initializes the struct, with all syscalls in table set to enable.
//
// max is the largest syscall number in table.
func (e *SyscallFlagsTable) init(table map[uintptr]Syscall, max uintptr) {
	e.enable = make([]uint32, max+1)
	for num := range table {
		e.enable[num] = syscallPresent
	}
}

// Word returns the enable bitfield for sysno.
func (e *SyscallFlagsTable) Word(sysno uintptr) uint32 {
	if sysno < uintptr(len(e.enable)) {
		return atomic.LoadUint32(&e.enable[sysno])
	}

	return atomic.LoadUint32(&e.missingEnable)
}

// Enable sets enable bit bit for all syscalls based on s.
//
// Syscalls missing from s are disabled.
//
// Syscalls missing from the initial table passed to Init cannot be added as
// individual syscalls. If present in s they will be ignored.
//
// Callers to Word may see either the old or new value while this function
// is executing.
func (e *SyscallFlagsTable) Enable(bit uint32, s map[uintptr]bool, missingEnable bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	missingVal := atomic.LoadUint32(&e.missingEnable)
	if missingEnable {
		missingVal |= bit
	} else {
		missingVal &^= bit
	}
	atomic.StoreUint32(&e.missingEnable, missingVal)

	for num := range e.enable {
		val := atomic.LoadUint32(&e.enable[num])
		if !bits.IsOn32(val, syscallPresent) {
			// Missing.
			atomic.StoreUint32(&e.enable[num], missingVal)
			continue
		}

		if s[uintptr(num)] {
			val |= bit
		} else {
			val &^= bit
		}
		atomic.StoreUint32(&e.enable[num], val)
	}
}

// EnableAll sets enable bit bit for all syscalls, present and missing.
func (e *SyscallFlagsTable) EnableAll(bit uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	missingVal := atomic.LoadUint32(&e.missingEnable)
	missingVal |= bit
	atomic.StoreUint32(&e.missingEnable, missingVal)

	for num := range e.enable {
		val := atomic.LoadUint32(&e.enable[num])
		if !bits.IsOn32(val, syscallPresent) {
			// Missing.
			atomic.StoreUint32(&e.enable[num], missingVal)
			continue
		}

		val |= bit
		atomic.StoreUint32(&e.enable[num], val)
	}
}

// Stracer traces syscall execution.
type Stracer interface {
	// SyscallEnter is called on syscall entry.
	//
	// The returned private data is passed to SyscallExit.
	SyscallEnter(t *Task, sysno uintptr, args arch.SyscallArguments, flags uint32) interface{}

	// SyscallExit is called on syscall exit.
	SyscallExit(context interface{}, t *Task, sysno, rval uintptr, err error)
}

// SyscallTable is a lookup table of system calls.
//
// Note that a SyscallTable is not savable directly. Instead, they are saved as
// an OS/Arch pair and lookup happens again on restore.
type SyscallTable struct {
	// OS is the operating system that this syscall table implements.
	OS abi.OS

	// Arch is the architecture that this syscall table targets.
	Arch arch.Arch

	// The OS version that this syscall table implements.
	Version Version

	// AuditNumber is a numeric constant that represents the syscall table. If
	// non-zero, auditNumber must be one of the AUDIT_ARCH_* values defined by
	// linux/audit.h.
	AuditNumber uint32

	// Table is the collection of functions.
	Table map[uintptr]Syscall

	// lookup is a fixed-size array that holds the syscalls (indexed by
	// their numbers). It is used for fast look ups.
	lookup []SyscallFn

	// Emulate is a collection of instruction addresses to emulate. The
	// keys are addresses, and the values are system call numbers.
	Emulate map[usermem.Addr]uintptr

	// The function to call in case of a missing system call.
	Missing MissingFn

	// Stracer traces this syscall table.
	Stracer Stracer

	// External is used to handle an external callback.
	External func(*Kernel)

	// ExternalFilterBefore is called before External is called before the syscall is executed.
	// External is not called if it returns false.
	ExternalFilterBefore func(*Task, uintptr, arch.SyscallArguments) bool

	// ExternalFilterAfter is called before External is called after the syscall is executed.
	// External is not called if it returns false.
	ExternalFilterAfter func(*Task, uintptr, arch.SyscallArguments) bool

	// FeatureEnable stores the strace and one-shot enable bits.
	FeatureEnable SyscallFlagsTable
}

// MaxSysno returns the largest system call number.
func (s *SyscallTable) MaxSysno() (max uintptr) {
	for num := range s.Table {
		if num > max {
			max = num
		}
	}
	return max
}

// allSyscallTables contains all known tables.
var allSyscallTables []*SyscallTable

// SyscallTables returns a read-only slice of registered SyscallTables.
func SyscallTables() []*SyscallTable {
	return allSyscallTables
}

// LookupSyscallTable returns the SyscallCall table for the OS/Arch combination.
func LookupSyscallTable(os abi.OS, a arch.Arch) (*SyscallTable, bool) {
	for _, s := range allSyscallTables {
		if s.OS == os && s.Arch == a {
			return s, true
		}
	}
	return nil, false
}

// RegisterSyscallTable registers a new syscall table for use by a Kernel.
func RegisterSyscallTable(s *SyscallTable) {
	if max := s.MaxSysno(); max > maxSyscallNum {
		panic(fmt.Sprintf("SyscallTable %+v contains too large syscall number %d", s, max))
	}
	if _, ok := LookupSyscallTable(s.OS, s.Arch); ok {
		panic(fmt.Sprintf("Duplicate SyscallTable registered for OS %v Arch %v", s.OS, s.Arch))
	}
	allSyscallTables = append(allSyscallTables, s)
	s.Init()
}

// Init initializes the system call table.
//
// This should normally be called only during registration.
func (s *SyscallTable) Init() {
	if s.Table == nil {
		// Ensure non-nil lookup table.
		s.Table = make(map[uintptr]Syscall)
	}
	if s.Emulate == nil {
		// Ensure non-nil emulate table.
		s.Emulate = make(map[usermem.Addr]uintptr)
	}

	max := s.MaxSysno() // Checked during RegisterSyscallTable.

	// Initialize the fast-lookup table.
	s.lookup = make([]SyscallFn, max+1)
	for num, sc := range s.Table {
		s.lookup[num] = sc.Fn
	}

	// Initialize all features.
	s.FeatureEnable.init(s.Table, max)
}

// Lookup returns the syscall implementation, if one exists.
func (s *SyscallTable) Lookup(sysno uintptr) SyscallFn {
	if sysno < uintptr(len(s.lookup)) {
		return s.lookup[sysno]
	}

	return nil
}

// LookupName looks up a syscall name.
func (s *SyscallTable) LookupName(sysno uintptr) string {
	if sc, ok := s.Table[sysno]; ok {
		return sc.Name
	}
	return fmt.Sprintf("sys_%d", sysno) // Unlikely.
}

// LookupNo looks up a syscall number by name.
func (s *SyscallTable) LookupNo(name string) (uintptr, error) {
	for i, syscall := range s.Table {
		if syscall.Name == name {
			return uintptr(i), nil
		}
	}
	return 0, fmt.Errorf("syscall %q not found", name)
}

// LookupEmulate looks up an emulation syscall number.
func (s *SyscallTable) LookupEmulate(addr usermem.Addr) (uintptr, bool) {
	sysno, ok := s.Emulate[addr]
	return sysno, ok
}

// mapLookup is similar to Lookup, except that it only uses the syscall table,
// that is, it skips the fast look array. This is available for benchmarking.
func (s *SyscallTable) mapLookup(sysno uintptr) SyscallFn {
	if sc, ok := s.Table[sysno]; ok {
		return sc.Fn
	}
	return nil
}
