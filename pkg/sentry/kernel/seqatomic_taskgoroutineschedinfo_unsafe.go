package kernel

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in seq.
//
//go:nosplit
func SeqAtomicLoadTaskGoroutineSchedInfo(seq *sync.SeqCount, ptr *TaskGoroutineSchedInfo) TaskGoroutineSchedInfo {
	for {
		if val, ok := SeqAtomicTryLoadTaskGoroutineSchedInfo(seq, seq.BeginRead(), ptr); ok {
			return val
		}
	}
}

// SeqAtomicTryLoad returns a copy of *ptr while in a reader critical section
// in seq initiated by a call to seq.BeginRead() that returned epoch. If the
// read would race with a writer critical section, SeqAtomicTryLoad returns
// (unspecified, false).
//
//go:nosplit
func SeqAtomicTryLoadTaskGoroutineSchedInfo(seq *sync.SeqCount, epoch sync.SeqCountEpoch, ptr *TaskGoroutineSchedInfo) (val TaskGoroutineSchedInfo, ok bool) {
	if sync.RaceEnabled {

		gohacks.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {

		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}
