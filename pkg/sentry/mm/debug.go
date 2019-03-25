// Copyright 2018 Google LLC
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

package mm

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

const (
	// If checkInvariants is true, perform runtime checks for invariants
	// expected by the mm package. This is normally disabled since MM is a
	// significant hot path in general, and some such checks (notably
	// memmap.CheckTranslateResult) are very expensive.
	checkInvariants = false

	// If logIOErrors is true, log I/O errors that originate from MM before
	// converting them to EFAULT.
	logIOErrors = false
)

// String implements fmt.Stringer.String.
func (mm *MemoryManager) String() string {
	return mm.DebugString(context.Background())
}

// DebugString returns a string containing information about mm for debugging.
func (mm *MemoryManager) DebugString(ctx context.Context) string {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	mm.activeMu.RLock()
	defer mm.activeMu.RUnlock()
	return mm.debugStringLocked(ctx)
}

// Preconditions: mm.mappingMu and mm.activeMu must be locked.
func (mm *MemoryManager) debugStringLocked(ctx context.Context) string {
	var b bytes.Buffer
	b.WriteString("VMAs:\n")
	for vseg := mm.vmas.FirstSegment(); vseg.Ok(); vseg = vseg.NextSegment() {
		b.Write(mm.vmaMapsEntryLocked(ctx, vseg))
	}
	b.WriteString("PMAs:\n")
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		b.Write(pseg.debugStringEntryLocked())
	}
	return string(b.Bytes())
}

// Preconditions: mm.activeMu must be locked.
func (pseg pmaIterator) debugStringEntryLocked() []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "%08x-%08x ", pseg.Start(), pseg.End())

	pma := pseg.ValuePtr()
	if pma.effectivePerms.Read {
		b.WriteByte('r')
	} else {
		b.WriteByte('-')
	}
	if pma.effectivePerms.Write {
		if pma.needCOW {
			b.WriteByte('c')
		} else {
			b.WriteByte('w')
		}
	} else {
		b.WriteByte('-')
	}
	if pma.effectivePerms.Execute {
		b.WriteByte('x')
	} else {
		b.WriteByte('-')
	}
	if pma.private {
		b.WriteByte('p')
	} else {
		b.WriteByte('s')
	}

	fmt.Fprintf(&b, " %08x %T\n", pma.off, pma.file)
	return b.Bytes()
}
