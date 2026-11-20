// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// DeviceAny matches any device major or minor number in a DeviceRule.
const DeviceAny = -1

// DeviceRule allows access to a device from a cgroup that otherwise denies
// access to all devices.
type DeviceRule struct {
	// Type is "c" for character devices or "b" for block devices.
	Type string `json:"type"`
	// Major is the device's major number, or DeviceAny.
	Major int64 `json:"major"`
	// Minor is the device's minor number, or DeviceAny.
	Minor int64 `json:"minor"`
	// Access is any combination of 'r' (read), 'w' (write) and 'm' (mknod).
	Access string `json:"access"`
}

// String returns the rule in the devices cgroup's "type major:minor access"
// format.
func (r DeviceRule) String() string {
	num := func(n int64) string {
		if n == DeviceAny {
			return "*"
		}
		return strconv.FormatInt(n, 10)
	}
	return fmt.Sprintf("%s %s:%s %s", r.Type, num(r.Major), num(r.Minor), r.Access)
}

// AllowDevices implements Cgroup.AllowDevices.
func (c *cgroupV1) AllowDevices(rules []DeviceRule) error {
	path := c.MakePath("devices")
	dir, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("devices cgroup controller is not mounted, so the sandbox cannot be confined: %w", err)
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	// Sandboxes that share the cgroup take turns extending its list.
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking cgroup: %w", err)
	}
	defer unix.Flock(int(dir.Fd()), unix.LOCK_UN)
	list, err := getValue(path, "devices.list")
	if err != nil {
		return err
	}
	// A new cgroup allows every device; deny them all so that only the rules
	// apply. The kernel merges a rule into the entry it already has for the
	// device.
	if strings.HasPrefix(list, "a ") {
		if err := setValue(path, "devices.deny", "a"); err != nil {
			return err
		}
	}
	for _, r := range rules {
		if err := setValue(path, "devices.allow", r.String()); err != nil {
			return err
		}
	}
	return nil
}

// devicesXattr holds, on the cgroup's directory, a deviceState recording what
// AllowDevices has allowed. It lives as long as the cgroup, so every process
// that extends the cgroup sees the rules applied before it.
const devicesXattr = "trusted.gvisor.devices"

// deviceState is the content of devicesXattr.
type deviceState struct {
	// Rules are the rules allowed so far.
	Rules []DeviceRule `json:"rules"`
	// Filter is the ID of the BPF program attached to the cgroup that allows
	// Rules, or 0 if none is.
	Filter uint32 `json:"filter"`
}

// AllowDevices implements Cgroup.AllowDevices.
func (c *cgroupV2) AllowDevices(rules []DeviceRule) error {
	dir, err := os.Open(c.MakePath(""))
	if err != nil {
		return err
	}
	defer dir.Close()
	target := int(dir.Fd())
	if err := unix.Flock(target, unix.LOCK_EX); err != nil {
		return fmt.Errorf("locking cgroup: %w", err)
	}
	defer unix.Flock(target, unix.LOCK_UN)
	state, err := readDeviceState(target)
	if err != nil {
		return err
	}
	missing := missingDeviceRules(state.Rules, rules)
	if state.Filter != 0 && len(missing) == 0 {
		return nil
	}
	state.Rules = append(state.Rules, missing...)
	insns, err := deviceFilter(state.Rules)
	if err != nil {
		return err
	}
	prog, err := bpfProgLoad(insns)
	if err != nil {
		return fmt.Errorf("loading device filter: %w", err)
	}
	defer unix.Close(prog)
	id, err := bpfProgID(prog)
	if err != nil {
		return fmt.Errorf("identifying device filter: %w", err)
	}
	if err := replaceDeviceFilter(target, prog, state.Filter); err != nil {
		return err
	}
	state.Filter = id
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return unix.Fsetxattr(target, devicesXattr, data, 0)
}

// readDeviceState returns the state recorded on the cgroup directory fd, or
// the zero state if none is.
func readDeviceState(fd int) (deviceState, error) {
	var state deviceState
	size, err := unix.Fgetxattr(fd, devicesXattr, nil)
	if errors.Is(err, unix.ENODATA) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("reading %s: %w", devicesXattr, err)
	}
	data := make([]byte, size)
	if size, err = unix.Fgetxattr(fd, devicesXattr, data); err != nil {
		return state, fmt.Errorf("reading %s: %w", devicesXattr, err)
	}
	if err := json.Unmarshal(data[:size], &state); err != nil {
		return state, fmt.Errorf("parsing %s: %w", devicesXattr, err)
	}
	return state, nil
}

// missingDeviceRules returns the rules that are not in allowed.
func missingDeviceRules(allowed, rules []DeviceRule) []DeviceRule {
	var missing []DeviceRule
	for _, r := range rules {
		if !slices.Contains(allowed, r) {
			missing = append(missing, r)
		}
	}
	return missing
}

// replaceDeviceFilter attaches prog to the cgroup directory fd target in place
// of the device filter with ID old, or alongside the filters attached to the
// cgroup if old is 0. Filters attached by others stay.
func replaceDeviceFilter(target, prog int, old uint32) error {
	replace := -1
	if old != 0 {
		fd, err := bpfProgGetFDByID(old)
		if err != nil {
			return fmt.Errorf("opening old device filter: %w", err)
		}
		defer unix.Close(fd)
		replace = fd
	}
	if err := bpfProgAttach(target, prog, replace); err != nil {
		return fmt.Errorf("attaching device filter: %w", err)
	}
	return nil
}

// insn is a BPF instruction (struct bpf_insn).
type insn struct {
	Op  uint8
	Reg uint8 // The destination register in the low nibble, the source in the high one.
	Off int16
	Imm int32
}

const (
	r0 uint8 = iota
	r1
	r2
	r3
	r4
	r5
)

func ldxw(dst, src uint8, off int16) insn {
	return insn{Op: unix.BPF_LDX | unix.BPF_MEM | unix.BPF_W, Reg: dst | src<<4, Off: off}
}

func alu32(op, dst uint8, imm int32) insn {
	return insn{Op: unix.BPF_ALU | op | unix.BPF_K, Reg: dst, Imm: imm}
}

func mov32(dst, src uint8) insn {
	return insn{Op: unix.BPF_ALU | unix.BPF_MOV | unix.BPF_X, Reg: dst | src<<4}
}

func jneImm(dst uint8, imm int32) insn {
	return insn{Op: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_K, Reg: dst, Imm: imm}
}

func jneReg(dst, src uint8) insn {
	return insn{Op: unix.BPF_JMP | unix.BPF_JNE | unix.BPF_X, Reg: dst | src<<4}
}

var exit = insn{Op: unix.BPF_JMP | unix.BPF_EXIT}

func (i insn) isJump() bool {
	return i.Op&0x07 == unix.BPF_JMP && i.Op&0xf0 == unix.BPF_JNE
}

// deviceFilter returns a BPF_PROG_TYPE_CGROUP_DEVICE program that allows
// exactly the accesses matched by rules.
func deviceFilter(rules []DeviceRule) ([]insn, error) {
	// The program is called with a struct bpf_cgroup_dev_ctx, whose 32-bit
	// fields are the access type (the device type in the low 16 bits and the
	// access in the high 16 bits), the major number and the minor number.
	prog := []insn{
		ldxw(r2, r1, 0),
		alu32(unix.BPF_AND, r2, 0xffff),
		ldxw(r3, r1, 0),
		alu32(unix.BPF_RSH, r3, 16),
		ldxw(r4, r1, 4),
		ldxw(r5, r1, 8),
	}
	const allAccess = unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE | unix.BPF_DEVCG_ACC_MKNOD
	for _, r := range rules {
		var typ int32
		switch r.Type {
		case "c":
			typ = unix.BPF_DEVCG_DEV_CHAR
		case "b":
			typ = unix.BPF_DEVCG_DEV_BLOCK
		default:
			return nil, fmt.Errorf("invalid device type in rule %q", r)
		}
		var access int32
		for _, c := range r.Access {
			switch c {
			case 'r':
				access |= unix.BPF_DEVCG_ACC_READ
			case 'w':
				access |= unix.BPF_DEVCG_ACC_WRITE
			case 'm':
				access |= unix.BPF_DEVCG_ACC_MKNOD
			default:
				return nil, fmt.Errorf("invalid device access in rule %q", r)
			}
		}
		if access == 0 || r.Major > math.MaxInt32 || r.Minor > math.MaxInt32 {
			return nil, fmt.Errorf("invalid device rule %q", r)
		}
		// Each rule is a block whose jumps skip the rest of the block on a
		// mismatch.
		block := []insn{jneImm(r2, typ)}
		if access != allAccess {
			block = append(block, mov32(r1, r3), alu32(unix.BPF_AND, r1, access), jneReg(r1, r3))
		}
		if r.Major != DeviceAny {
			block = append(block, jneImm(r4, int32(r.Major)))
		}
		if r.Minor != DeviceAny {
			block = append(block, jneImm(r5, int32(r.Minor)))
		}
		block = append(block, alu32(unix.BPF_MOV, r0, 1), exit)
		for i := range block {
			if block[i].isJump() {
				block[i].Off = int16(len(block) - 1 - i)
			}
		}
		prog = append(prog, block...)
	}
	return append(prog, alu32(unix.BPF_MOV, r0, 0), exit), nil
}
