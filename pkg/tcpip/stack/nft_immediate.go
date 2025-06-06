// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

// immediate is an operation that sets the data in a register.
type immediate struct {
	data registerData // Data to set the destination register to.
	dreg uint8        // Number of the destination register.
}

// newImmediate creates a new immediate operation.
func newImmediate(dreg uint8, data registerData) (*immediate, error) {
	if err := data.validateRegister(dreg); err != nil {
		return nil, err
	}
	return &immediate{dreg: dreg, data: data}, nil
}

// evaluate for Immediate sets the data in the destination register.
func (op immediate) evaluate(regs *registerSet, pkt *PacketBuffer, rule *NFRule) {
	op.data.storeData(regs, op.dreg)
}
