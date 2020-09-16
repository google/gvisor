package kernel

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"

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

		sync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {

		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}

func initTaskGoroutineSchedInfo() {
	var val TaskGoroutineSchedInfo
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := sync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
