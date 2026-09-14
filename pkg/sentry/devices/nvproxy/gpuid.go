// Copyright 2026 The gVisor Authors.
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

package nvproxy

import (
	"fmt"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Translation of device identifiers across a restore that remapped devices.
//
// Two families of identifier cross the nvproxy boundary and are properties of
// the host rather than of the sandbox:
//
//   - the "device instance", NV0080_ALLOC_PARAMETERS::deviceId, remapped in
//     saved objects by nvproxy.afterLoad();
//   - the "gpuId", nv_state_t::gpu_id, which the driver generates from PCI
//     information and which therefore differs on a different physical GPU.
//
// The application's user-mode driver caches both from before the checkpoint,
// so an untranslated one reaching it is read as naming a device it does not
// have. Identifiers travel in both directions: outward, where a host value
// must be reported as the guest value the application remembers, and inward,
// where a guest value must be resolved to the host value the driver expects.

// idMaps bundles the translation tables for one nvproxy. The tables
// themselves are saved fields of nvproxy; this is only a value bundle so that
// the pure helpers below can be tested without a sandbox.
//
// The guestToHost maps are the inverses of the hostToGuest maps. They are
// stored rather than inverted on demand so that a restore with no remapping
// (which does not run the composition) still has them.
type idMaps struct {
	// HostToGuestDeviceInstance maps a host device instance to the device
	// instance the application saw before the most recent checkpoint.
	HostToGuestDeviceInstance map[uint32]uint32

	// GuestToHostDeviceInstance is the inverse of HostToGuestDeviceInstance.
	GuestToHostDeviceInstance map[uint32]uint32

	// HostToGuestGPUID maps a host gpuId to the gpuId the application saw
	// before the most recent checkpoint.
	HostToGuestGPUID map[uint32]uint32

	// GuestToHostGPUID is the inverse of HostToGuestGPUID.
	GuestToHostGPUID map[uint32]uint32

	// HostToGuestUUID maps a host GPU UUID string, "GPU-" prefix included, to
	// the UUID the application saw before the most recent checkpoint.
	HostToGuestUUID map[string]string

	// HostToGuestPCIAddr and GuestToHostPCIAddr map packed PCI addresses; see
	// PackPCIAddr.
	HostToGuestPCIAddr map[uint64]uint64
	GuestToHostPCIAddr map[uint64]uint64
}

// empty returns true if no restore has established any translation.
func (m idMaps) empty() bool {
	return len(m.HostToGuestDeviceInstance) == 0 && len(m.HostToGuestGPUID) == 0
}

// composeIDMap returns the host-to-guest mapping produced by applying the
// old-to-new pairs in remap on top of prev, where prev is the mapping
// established by a previous restore (nil if there was none).
//
// It is pure. Each remapping is composed with the one before it rather than
// replacing it, so that a sandbox restored twice still reports the identifiers
// of its original boot. An old identifier absent from prev was never remapped
// and is therefore its own guest identifier.
func composeIDMap(prev map[uint32]uint32, remap [][2]uint32) map[uint32]uint32 {
	return composeMap(prev, remap)
}

// composeMap is composeIDMap for any identifier type. Every family of
// identifier composes the same way, so they share one implementation.
func composeMap[T comparable](prev map[T]T, remap [][2]T) map[T]T {
	next := make(map[T]T, len(remap))
	for _, pair := range remap {
		oldID, newID := pair[0], pair[1]
		guest := oldID
		if g, ok := prev[oldID]; ok {
			guest = g
		}
		next[newID] = guest
	}
	return next
}

// invertMap is invertIDMap for any identifier type.
func invertMap[T comparable](m map[T]T, what string) map[T]T {
	inv := make(map[T]T, len(m))
	collided := make(map[T]struct{})
	for host, guest := range m {
		if prevHost, ok := inv[guest]; ok {
			log.Warningf("nvproxy: %s mapping is not injective: guest %v is the image of both host %v and host %v; neither will be translated inward", what, guest, prevHost, host)
			collided[guest] = struct{}{}
			continue
		}
		inv[guest] = host
	}
	for guest := range collided {
		delete(inv, guest)
	}
	return inv
}

// PackPCIAddr encodes a PCI address as one value: domain in bits 63:24, bus in
// 23:16, slot (device) in 15:8 and function in 7:0. Exported because
// runsc/boot fills DeviceRemapIDs.
func PackPCIAddr(domain uint32, bus, slot, function uint8) uint64 {
	return uint64(domain)<<24 | uint64(bus)<<16 | uint64(slot)<<8 | uint64(function)
}

// UnpackPCIAddr is the inverse of PackPCIAddr.
func UnpackPCIAddr(v uint64) (domain uint32, bus, slot, function uint8) {
	return uint32(v >> 24), uint8(v >> 16), uint8(v >> 8), uint8(v)
}

// formatPCIAddrMap renders a PCI address mapping in ascending key order.
func formatPCIAddrMap(m map[uint64]uint64) string {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s -> %s", formatPCIAddr(k), formatPCIAddr(m[k]))
	}
	b.WriteByte('}')
	return b.String()
}

// formatPCIAddr renders a packed PCI address conventionally.
func formatPCIAddr(v uint64) string {
	domain, bus, slot, function := UnpackPCIAddr(v)
	return fmt.Sprintf("%04x:%02x:%02x.%x", domain, bus, slot, function)
}

// invertIDMap returns the inverse of m. A host identifier that is not the
// image of exactly one guest identifier is dropped with a warning rather than
// silently overwriting a sibling: an ambiguous inverse would resolve a guest
// identifier to the wrong device, which is worse than not resolving it.
func invertIDMap(m map[uint32]uint32, what string) map[uint32]uint32 {
	return invertMap(m, what)
}

// formatIDMap renders m in ascending key order, since Go map iteration order
// would otherwise vary from one log line to the next.
func formatIDMap(m map[uint32]uint32) string {
	keys := make([]uint32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d -> %d", k, m[k])
	}
	b.WriteByte('}')
	return b.String()
}

// permuteDeviceInstanceMask translates a bitmask whose set bits are device
// instances, using m. A set bit whose device instance is not in m is carried
// through unchanged, matching the scalar translations.
func permuteDeviceInstanceMask(mask uint32, m map[uint32]uint32) uint32 {
	if len(m) == 0 {
		return mask
	}
	var out uint32
	for bit := uint32(0); bit < 32; bit++ {
		if mask&(1<<bit) == 0 {
			continue
		}
		to := bit
		if t, ok := m[bit]; ok {
			if t >= 32 {
				// Cannot be represented in the mask. Keep the original bit
				// rather than dropping the device entirely.
				log.Warningf("nvproxy: device instance %d translates to %d, which does not fit in a 32-bit device mask", bit, t)
				to = bit
			} else {
				to = t
			}
		}
		out |= 1 << to
	}
	return out
}

// translateID returns the translation of id under m, and whether one was
// found. NV0000_CTRL_GPU_INVALID_ID is never translated: it is the terminator
// of every gpuId array the driver fills.
func translateID(id uint32, m map[uint32]uint32) (uint32, bool) {
	if id == nvgpu.NV0000_CTRL_GPU_INVALID_ID {
		return id, false
	}
	to, ok := m[id]
	return to, ok
}

// idDirection says which way a translated field moves.
type idDirection int

const (
	// idIn is a field the application supplies: a guest identifier that must
	// be resolved to a host identifier before the ioctl, and put back
	// afterwards so that the application reads its own value again.
	idIn idDirection = iota

	// idOut is a field the driver fills: a host identifier that must be
	// reported as a guest identifier after the ioctl.
	idOut
)

// idKind says which family of identifier a field holds.
type idKind int

const (
	idGPUID idKind = iota
	idDeviceInstance
	idDeviceInstanceMask
)

// rawIDField describes one run of NvU32 identifiers inside a control's
// parameter buffer, by byte offset rather than by a Go struct. These controls
// are proxied as opaque bytes by rmControlSimple, and modelling them as
// marshallable structs would make a driver whose layout differs by a field
// fail outright; addressing them by offset lets a size check fall back to
// passing the buffer through untouched.
type rawIDField struct {
	// Kind and Dir say what the field holds and which way it moves.
	Kind idKind
	Dir  idDirection

	// Offset is the byte offset of the first element.
	Offset int

	// Count is the number of elements.
	Count int

	// Stride is the byte distance between elements. Zero means 4, i.e. a
	// contiguous NvU32 array.
	Stride int

	// CountAt, if non-negative, is the byte offset of an NvU32 that bounds
	// Count: only the first that many elements are translated.
	CountAt int
}

// stride returns f.Stride, defaulting to the size of an NvU32.
func (f rawIDField) stride() int {
	if f.Stride == 0 {
		return 4
	}
	return f.Stride
}

// end returns the byte offset one past the last element of f.
func (f rawIDField) end() int {
	return f.Offset + (f.Count-1)*f.stride() + 4
}

// rawIDSpec describes every identifier field in one control's parameters.
type rawIDSpec struct {
	// Name is the control's NV0000_CTRL_CMD_* name, for logging.
	Name string

	// Size is the parameter size this layout was modelled from. A control
	// whose ParamsSize differs is passed through untranslated: the layout on
	// that driver is not the one described here.
	Size int

	Fields []rawIDField
}

// minSize returns the smallest buffer every field of s fits in.
func (s *rawIDSpec) minSize() int {
	n := 0
	for _, f := range s.Fields {
		if e := f.end(); e > n {
			n = e
		}
	}
	return n
}

// rawIDSpecs describes the controls that carry identifiers in a parameter
// layout nvproxy does not otherwise model. Offsets and sizes are from
// src/common/sdk/nvidia/inc/ctrl/ctrl0000/{ctrl0000gpu.h,ctrl0000system.h} at
// driver 610.
var rawIDSpecs = map[uint32]*rawIDSpec{
	// NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS{gpuIds[32]}.
	nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS: {
		Name: "NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS",
		Size: 4 * nvgpu.NV0000_CTRL_GPU_MAX_ATTACHED_GPUS,
		Fields: []rawIDField{
			{Kind: idGPUID, Dir: idOut, Offset: 0, Count: nvgpu.NV0000_CTRL_GPU_MAX_ATTACHED_GPUS, CountAt: -1},
		},
	},

	// NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS{gpuIds[32], excludedGpuIds[32],
	// gpuFlags[32]}.
	nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS: {
		Name: "NV0000_CTRL_CMD_GPU_GET_PROBED_IDS",
		Size: 3 * 4 * nvgpu.NV0000_CTRL_GPU_MAX_PROBED_GPUS,
		Fields: []rawIDField{
			{Kind: idGPUID, Dir: idOut, Offset: 0, Count: nvgpu.NV0000_CTRL_GPU_MAX_PROBED_GPUS, CountAt: -1},
			{Kind: idGPUID, Dir: idOut, Offset: 4 * nvgpu.NV0000_CTRL_GPU_MAX_PROBED_GPUS, Count: nvgpu.NV0000_CTRL_GPU_MAX_PROBED_GPUS, CountAt: -1},
		},
	},

	// NV0000_CTRL_GPU_GET_DEVICE_IDS_PARAMS{deviceIds}, a bitmask of device
	// instances rather than a list of gpuIds despite the name.
	nvgpu.NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS: {
		Name: "NV0000_CTRL_CMD_GPU_GET_DEVICE_IDS",
		Size: 4,
		Fields: []rawIDField{
			{Kind: idDeviceInstanceMask, Dir: idOut, Offset: 0, Count: 1, CountAt: -1},
		},
	},

	// NV0000_CTRL_GPU_GET_ACTIVE_DEVICE_IDS_PARAMS{numDevices,
	// NV0000_CTRL_GPU_ACTIVE_DEVICE devices[256]}, each device being
	// {gpuId, gpuInstanceId, computeInstanceId}. The latter two are MIG
	// instance ids and are not translated.
	nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS: {
		Name: "NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS",
		Size: 4 + 12*nvgpu.NV0000_CTRL_GPU_MAX_ACTIVE_DEVICES,
		Fields: []rawIDField{
			{Kind: idGPUID, Dir: idOut, Offset: 4, Count: nvgpu.NV0000_CTRL_GPU_MAX_ACTIVE_DEVICES, Stride: 12, CountAt: 0},
		},
	},

	// NV0000_CTRL_SYSTEM_GET_P2P_CAPS_V2_PARAMS{gpuIds[32], gpuCount,
	// p2pCaps, p2pOptimalReadCEs, p2pOptimalWriteCEs, p2pCapsStatus[9],
	// busPeerIds[1024], busEgmPeerIds[1024]}. The peer id arrays hold peer
	// indices, not gpuIds.
	nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2: {
		Name: "NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2",
		Size: 4*nvgpu.NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS + 4 + 4 + 4 + 4 + nvgpu.NV0000_CTRL_P2P_CAPS_INDEX_TABLE_SIZE + 3 +
			4*nvgpu.NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS_SQUARED + 4*nvgpu.NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS_SQUARED,
		Fields: []rawIDField{
			{Kind: idGPUID, Dir: idIn, Offset: 0, Count: nvgpu.NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS, CountAt: 4 * nvgpu.NV0000_CTRL_SYSTEM_MAX_ATTACHED_GPUS},
		},
	},

	// NV0000_CTRL_SYSTEM_GET_P2P_CAPS_MATRIX_PARAMS{grpACount, grpBCount,
	// gpuIdGrpA[8], gpuIdGrpB[8], then five [8][8] NvU32 matrices}.
	nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX: {
		Name: "NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX",
		Size: 4 + 4 + 4*nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS + 4*nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS +
			5*4*nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS*nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS,
		Fields: []rawIDField{
			{Kind: idGPUID, Dir: idIn, Offset: 8, Count: nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS, CountAt: 0},
			{Kind: idGPUID, Dir: idIn, Offset: 8 + 4*nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS, Count: nvgpu.NV0000_CTRL_SYSTEM_MAX_P2P_GROUP_GPUS, CountAt: 4},
		},
	},
}

// applyRawIDFields translates every field of spec whose direction is dir,
// in place in buf, using maps. It returns the number of values it changed.
//
// buf is the raw control parameter buffer. Preconditions: len(buf) == spec.Size.
// If inverse is true the opposite map is used, which is how an inbound field
// is put back to the value the application passed after the ioctl has read it.
func applyRawIDFields(buf []byte, spec *rawIDSpec, dir idDirection, inverse bool, maps idMaps, onTranslate func(kind idKind, from, to uint32)) int {
	changed := 0
	for _, f := range spec.Fields {
		if f.Dir != dir {
			continue
		}
		count := f.Count
		if f.CountAt >= 0 {
			if n := int(hostarch.ByteOrder.Uint32(buf[f.CountAt:])); n < count {
				count = n
			}
		}
		guestToHost := (dir == idIn) != inverse
		var m map[uint32]uint32
		switch f.Kind {
		case idGPUID:
			if guestToHost {
				m = maps.GuestToHostGPUID
			} else {
				m = maps.HostToGuestGPUID
			}
		case idDeviceInstance, idDeviceInstanceMask:
			if guestToHost {
				m = maps.GuestToHostDeviceInstance
			} else {
				m = maps.HostToGuestDeviceInstance
			}
		}
		if len(m) == 0 {
			continue
		}
		stride := f.stride()
		for i := 0; i < count; i++ {
			off := f.Offset + i*stride
			from := hostarch.ByteOrder.Uint32(buf[off:])
			var to uint32
			if f.Kind == idDeviceInstanceMask {
				to = permuteDeviceInstanceMask(from, m)
				if to == from {
					continue
				}
			} else {
				var ok bool
				to, ok = translateID(from, m)
				if !ok {
					continue
				}
			}
			hostarch.ByteOrder.PutUint32(buf[off:], to)
			changed++
			if onTranslate != nil {
				onTranslate(f.Kind, from, to)
			}
		}
	}
	return changed
}

// composeUUIDMap is composeIDMap for UUID strings.
func composeUUIDMap(prev map[string]string, remap [][2]string) map[string]string {
	return composeMap(prev, remap)
}

// formatUUIDMap renders m in ascending key order.
func formatUUIDMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s -> %s", k, m[k])
	}
	b.WriteByte('}')
	return b.String()
}

// uuidBinary parses a "GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" UUID string
// into the 16 raw bytes the driver reports in binary format, as produced by
// src/nvidia/src/kernel/gpu/gpu.c:gpuGetGidInfo_IMPL().
func uuidBinary(s string) ([16]byte, bool) {
	var out [16]byte
	hex := strings.TrimPrefix(s, "GPU-")
	hex = strings.ReplaceAll(hex, "-", "")
	if len(hex) != 32 {
		return out, false
	}
	for i := 0; i < 16; i++ {
		hi, ok := hexNibble(hex[2*i])
		if !ok {
			return out, false
		}
		lo, ok := hexNibble(hex[2*i+1])
		if !ok {
			return out, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// translateUUIDBytes rewrites a GPU UUID held in buf, in either the ASCII or
// the binary representation, from the host's to the guest's. It reports
// whether it changed anything.
//
// asciiLen bounds the ASCII form; pass 0 to use the whole of buf up to the
// first NUL.
func translateUUIDBytes(buf []byte, binary bool, m map[string]string) (from, to string, ok bool) {
	if len(m) == 0 {
		return "", "", false
	}
	if binary {
		if len(buf) < 16 {
			return "", "", false
		}
		for hostStr, guestStr := range m {
			hostBin, hostOK := uuidBinary(hostStr)
			guestBin, guestOK := uuidBinary(guestStr)
			if !hostOK || !guestOK {
				continue
			}
			if string(hostBin[:]) == string(buf[:16]) {
				copy(buf[:16], guestBin[:])
				return hostStr, guestStr, true
			}
		}
		return "", "", false
	}
	// ASCII: the driver writes a NUL-terminated string.
	end := len(buf)
	if i := indexByte(buf, 0); i >= 0 {
		end = i
	}
	hostStr := string(buf[:end])
	guestStr, found := m[hostStr]
	if !found {
		return "", "", false
	}
	if len(guestStr) > len(buf) {
		// Cannot happen with well-formed UUIDs, which are all the same
		// length, but refuse rather than truncate.
		log.Warningf("nvproxy: guest UUID %q does not fit in a %d-byte buffer", guestStr, len(buf))
		return "", "", false
	}
	copy(buf, guestStr)
	for i := len(guestStr); i < end; i++ {
		buf[i] = 0
	}
	return hostStr, guestStr, true
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// invertUUIDMap returns the inverse of m, dropping any guest UUID that is the
// image of more than one host UUID for the same reason invertIDMap does.
func invertUUIDMap(m map[string]string) map[string]string {
	return invertMap(m, "UUID")
}

// Identifier translation applies only to processes that were restored from the
// checkpoint. Those hold a user-mode driver whose tables are keyed by the
// identities the sandbox had before the checkpoint. A process created after
// the restore -- a forked child, an exec'd image, or a helper the checkpointer
// runs inside the sandbox after the restore, such as cuda-checkpoint --
// initialises CUDA against the devices that are actually present, so it must
// see the host's identities and the device files that exist. Translating for
// it hands it a device instance and a /dev/nvidia# that do not.
//
// Threads created later inside a restored process share its thread group, and
// so stay translated. That is intended: NCCL's proxy threads run against the
// driver state the process already had.

// translationScope is the answer to "should this ioctl be translated", plus
// the thread group it was decided for, which the Debug lines report so that
// the scoping can be checked against a log.
type translationScope struct {
	// Restored is true if the calling thread group existed at checkpoint time.
	Restored bool

	// TGID is the calling thread group's ID, or 0 if there is no task.
	TGID int32
}

// String implements fmt.Stringer.String.
func (s translationScope) String() string {
	return fmt.Sprintf("tgid=%d restored=%t", s.TGID, s.Restored)
}

// scopeFor returns the translation scope for a task. A nil task -- which
// happens on no current path, since object re-creation during restore issues
// its ioctls directly rather than through a handler -- is treated as not
// restored, the conservative answer: it passes host identities through
// unchanged, which is what nvproxy did before any of this existed.
func scopeFor(t *kernel.Task) translationScope {
	if t == nil {
		return translationScope{}
	}
	tg := t.ThreadGroup()
	if tg == nil {
		return translationScope{}
	}
	return translationScope{
		Restored: tg.ExistedAtCheckpoint(),
		TGID:     int32(tg.ID()),
	}
}

// permuteByDeviceInstance returns arr with each element moved from the index
// it occupied under one device-instance numbering to the index it occupies
// under the other. An index with no translation keeps its element.
func permuteByDeviceInstance(arr [nvgpu.NV_MAX_DEVICES]uint32, m map[uint32]uint32) [nvgpu.NV_MAX_DEVICES]uint32 {
	if len(m) == 0 {
		return arr
	}
	var out [nvgpu.NV_MAX_DEVICES]uint32
	moved := make(map[uint32]struct{}, len(m))
	for from, to := range m {
		if from >= uint32(len(arr)) || to >= uint32(len(arr)) {
			continue
		}
		out[to] = arr[from]
		moved[from] = struct{}{}
		moved[to] = struct{}{}
	}
	// Indices that no translation names, in either direction, keep what they
	// had.
	for i := range arr {
		if _, ok := moved[uint32(i)]; !ok {
			out[i] = arr[i]
		}
	}
	return out
}

// describeRawIDField renders the live values of one identifier field, bounded
// by its count field where it has one and stopping at the array terminator.
// It is for the Debug line that shows what a restored process actually
// enumerated: the identifiers it sees are what it keys its device table on.
func describeRawIDField(buf []byte, f rawIDField) string {
	count := f.Count
	if f.CountAt >= 0 && f.CountAt+4 <= len(buf) {
		if n := int(hostarch.ByteOrder.Uint32(buf[f.CountAt:])); n < count {
			count = n
		}
	}
	stride := f.stride()
	var b strings.Builder
	b.WriteByte('[')
	shown := 0
	for i := 0; i < count; i++ {
		off := f.Offset + i*stride
		if off+4 > len(buf) {
			break
		}
		v := hostarch.ByteOrder.Uint32(buf[off:])
		if f.Kind == idGPUID && v == nvgpu.NV0000_CTRL_GPU_INVALID_ID {
			// The terminator: nothing beyond it is meaningful.
			break
		}
		if shown != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d", v)
		shown++
	}
	b.WriteByte(']')
	return b.String()
}

// removeShadowedGPUIDs removes physical GPUs whose identifiers now name a
// different, remapped GPU in the guest. The remaining entries are still host
// IDs; translate them only after compacting the list and its parallel flags.
func removeShadowedGPUIDs(buf []byte, cmd uint32, maps idMaps) {
	switch cmd {
	case nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:
		compactGPUIDList(buf, 0, nvgpu.NV0000_CTRL_GPU_MAX_ATTACHED_GPUS, -1, maps)
	case nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:
		count := int(nvgpu.NV0000_CTRL_GPU_MAX_PROBED_GPUS)
		compactGPUIDList(buf, 0, count, 8*count, maps)
		compactGPUIDList(buf, 4*count, count, -1, maps)
	}
}

func compactGPUIDList(buf []byte, offset, count, flagsOffset int, maps idMaps) {
	dst := 0
	for src := 0; src < count; src++ {
		id := hostarch.ByteOrder.Uint32(buf[offset+4*src:])
		if id == nvgpu.NV0000_CTRL_GPU_INVALID_ID {
			break
		}
		_, mapped := maps.HostToGuestGPUID[id]
		_, shadowed := maps.GuestToHostGPUID[id]
		if shadowed && !mapped {
			continue
		}
		hostarch.ByteOrder.PutUint32(buf[offset+4*dst:], id)
		if flagsOffset >= 0 {
			flags := hostarch.ByteOrder.Uint32(buf[flagsOffset+4*src:])
			hostarch.ByteOrder.PutUint32(buf[flagsOffset+4*dst:], flags)
		}
		dst++
	}
	for ; dst < count; dst++ {
		hostarch.ByteOrder.PutUint32(buf[offset+4*dst:], nvgpu.NV0000_CTRL_GPU_INVALID_ID)
		if flagsOffset >= 0 {
			hostarch.ByteOrder.PutUint32(buf[flagsOffset+4*dst:], 0)
		}
	}
}
