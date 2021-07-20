// Copyright 2020 The gVisor Authors.
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

// limitPCID is the maximum value of PCIDs.
//
// In VMSAv8-64, the PCID(ASID) size is an IMPLEMENTATION DEFINED choice
// of 8 bits or 16 bits, and ID_AA64MMFR0_EL1.ASIDBits identifies the
// supported size. When an implementation supports a 16-bit ASID, TCR_ELx.AS
// selects whether the top 8 bits of the ASID are used.
var limitPCID uint16

// GetASIDBits return the system ASID bits, 8 or 16 bits.
func GetASIDBits() uint8

func init() {
	limitPCID = uint16(1)<<GetASIDBits() - 1
}
