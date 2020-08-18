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

// +build arm64

package ring0

// CPACREL1 returns the value of the CPACR_EL1 register.
func CPACREL1() (value uintptr)

// FPCR returns the value of FPCR register.
func GetFPCR() (value uintptr)

// SetFPCR writes the FPCR value.
func SetFPCR(value uintptr)

// FPSR returns the value of FPSR register.
func GetFPSR() (value uintptr)

// SetFPSR writes the FPSR value.
func SetFPSR(value uintptr)

// SaveVRegs saves V0-V31 registers.
// V0-V31: 32 128-bit registers for floating point and simd.
func SaveVRegs(*byte)

// LoadVRegs loads V0-V31 registers.
func LoadVRegs(*byte)

// LoadFloatingPoint loads floating point state.
func LoadFloatingPoint(*byte)

// SaveFloatingPoint saves floating point state.
func SaveFloatingPoint(*byte)

// GetTLS returns the value of TPIDR_EL0 register.
func GetTLS() (value uint64)

// SetTLS writes the TPIDR_EL0 value.
func SetTLS(value uint64)

// Init sets function pointers based on architectural features.
//
// This must be called prior to using ring0.
func Init() {
	rewriteVectors()
}
