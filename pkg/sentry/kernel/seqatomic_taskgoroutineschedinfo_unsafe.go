package kernel

import (
	"strings"
	"unsafe"

	"fmt"
	"gvisor.dev/gvisor/third_party/gvsync"
	"reflect"
)

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in sc.
func SeqAtomicLoadTaskGoroutineSchedInfo(sc *gvsync.SeqCount, ptr *TaskGoroutineSchedInfo) TaskGoroutineSchedInfo {
	// This function doesn't use SeqAtomicTryLoad because doing so is
	// measurably, significantly (~20%) slower; Go is awful at inlining.
	var val TaskGoroutineSchedInfo
	for {
		epoch := sc.BeginRead()
		if gvsync.RaceEnabled {

			gvsync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
		} else {

			val = *ptr
		}
		if sc.ReadOk(epoch) {
			break
		}
	}
	return val
}

// SeqAtomicTryLoad returns a copy of *ptr while in a reader critical section
// in sc initiated by a call to sc.BeginRead() that returned epoch. If the read
// would race with a writer critical section, SeqAtomicTryLoad returns
// (unspecified, false).
func SeqAtomicTryLoadTaskGoroutineSchedInfo(sc *gvsync.SeqCount, epoch gvsync.SeqCountEpoch, ptr *TaskGoroutineSchedInfo) (TaskGoroutineSchedInfo, bool) {
	var val TaskGoroutineSchedInfo
	if gvsync.RaceEnabled {
		gvsync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {
		val = *ptr
	}
	return val, sc.ReadOk(epoch)
}

func initTaskGoroutineSchedInfo() {
	var val TaskGoroutineSchedInfo
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := gvsync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
