package fuse

import (
	__generics_imported0 "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in seq.
//
//go:nosplit
func SeqAtomicLoadTime(seq *sync.SeqCount, ptr *__generics_imported0.Time) __generics_imported0.Time {
	for {
		if val, ok := SeqAtomicTryLoadTime(seq, seq.BeginRead(), ptr); ok {
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
func SeqAtomicTryLoadTime(seq *sync.SeqCount, epoch sync.SeqCountEpoch, ptr *__generics_imported0.Time) (val __generics_imported0.Time, ok bool) {
	if sync.RaceEnabled {

		gohacks.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {

		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}

// SeqAtomicStore sets *ptr to a copy of val, ensuring that any racing reader
// critical sections are forced to retry.
//
//go:nosplit
func SeqAtomicStoreTime(seq *sync.SeqCount, ptr *__generics_imported0.Time, val __generics_imported0.Time) {
	seq.BeginWrite()
	SeqAtomicStoreSeqedTime(ptr, val)
	seq.EndWrite()
}

// SeqAtomicStoreSeqed sets *ptr to a copy of val.
//
// Preconditions: ptr is protected by a SeqCount that will be in a writer
// critical section throughout the call to SeqAtomicStore.
//
//go:nosplit
func SeqAtomicStoreSeqedTime(ptr *__generics_imported0.Time, val __generics_imported0.Time) {
	if sync.RaceEnabled {
		gohacks.Memmove(unsafe.Pointer(ptr), unsafe.Pointer(&val), unsafe.Sizeof(val))
	} else {
		*ptr = val
	}
}
