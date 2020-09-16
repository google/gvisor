package time

import (
	"unsafe"

	"fmt"
	"gvisor.dev/gvisor/pkg/sync"
	"reflect"
	"strings"
)

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in seq.
//
//go:nosplit
func SeqAtomicLoadParameters(seq *sync.SeqCount, ptr *Parameters) Parameters {
	for {
		if val, ok := SeqAtomicTryLoadParameters(seq, seq.BeginRead(), ptr); ok {
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
func SeqAtomicTryLoadParameters(seq *sync.SeqCount, epoch sync.SeqCountEpoch, ptr *Parameters) (val Parameters, ok bool) {
	if sync.RaceEnabled {

		sync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {

		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}

func initParameters() {
	var val Parameters
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := sync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
