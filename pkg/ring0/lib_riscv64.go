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

//go:build riscv64
// +build riscv64

package ring0

// storeEl0Fpstate writes the address of application's fpstate.
func storeEl0Fpstate(value *byte)

// storeAppASID writes the application's asid value.
func storeAppASID(asid uintptr)

// LocalFlushTlbAll same as FlushTlbAll, but only applies to the calling CPU.
func LocalFlushTlbAll()

// FlushTlbByVA invalidates tlb by VA/Last-level/Inner-Shareable.
func FlushTlbByVA(addr uintptr)

// FlushTlbByASID invalidates tlb by ASID/Inner-Shareable.
func FlushTlbByASID(asid uintptr)

// LocalFlushTlbByASID invalidates tlb by ASID.
func LocalFlushTlbByASID(asid uintptr)

// FlushTlbAll invalidates all tlb.
func FlushTlbAll()

// CPACREL1 returns the value of the CPACR_EL1 register.
func CPACREL1() (value uintptr)

// GetFCSR returns the value of FCSR register.
func GetFCSR() (value uintptr)

// SetFCSR writes the FCSR value.
func SetFCSR(value uintptr)

// SaveFpRegs saves f0-f31 registers.
func SaveFpRegs(*byte)

// LoadFpRegs loads f0-f31 registers.
func LoadFpRegs(*byte)

// LoadFloatingPoint loads floating point state.
func LoadFloatingPoint(*byte)

// SaveFloatingPoint saves floating point state.
func SaveFloatingPoint(*byte)

// FPSIMDDisableTrap disables fpsimd.
func FPSIMDDisableTrap()

// FPSIMDEnableTrap enables fpsimd.
func FPSIMDEnableTrap()

// Init sets function pointers based on architectural features.
//
// This must be called prior to using ring0.
func Init() {}

// InitDefault calls Init with default parameters.
// On ARM, this is not much.
func InitDefault() {}
