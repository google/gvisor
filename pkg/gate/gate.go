// Package gate provides a usage Gate synchronization primitive.
package gate

import (
	"sync/atomic"
)

const (
	// gateClosed is the bit set in the gate's user count to indicate that
	// it has been closed. It is the MSB of the 32-bit field; the other 31
	// bits carry the actual count.
	gateClosed = 0x80000000
)

// Gate is a synchronization primitive that allows concurrent goroutines to
// "enter" it as long as it hasn't been closed yet. Once it's been closed,
// goroutines cannot enter it anymore, but are allowed to leave, and the closer
// will be informed when all goroutines have left.
//
// Many goroutines are allowed to enter the gate concurrently, but only one is
// allowed to close it.
//
// This is similar to a r/w critical section, except that goroutines "entering"
// never block: they either enter immediately or fail to enter. The closer will
// block waiting for all goroutines currently inside the gate to leave.
//
// This function is implemented efficiently. On x86, only one interlocked
// operation is performed on enter, and one on leave.
//
// This is useful, for example, in cases when a goroutine is trying to clean up
// an object for which multiple goroutines have pointers. In such a case, users
// would be required to enter and leave the gates, and the cleaner would wait
// until all users are gone (and no new ones are allowed) before proceeding.
//
// Users:
//
//	if !g.Enter() {
//		// Gate is closed, we can't use the object.
//		return
//	}
//
//	// Do something with object.
//	[...]
//
//	g.Leave()
//
// Closer:
//
//	// Prevent new users from using the object, and wait for the existing
//	// ones to complete.
//	g.Close()
//
//	// Clean up the object.
//	[...]
//
type Gate struct {
	userCount uint32
	done      chan struct{}
}

// Enter tries to enter the gate. It will succeed if it hasn't been closed yet,
// in which case the caller must eventually call Leave().
//
// This function is thread-safe.
func (g *Gate) Enter() bool {
	if g == nil {
		return false
	}

	for {
		v := atomic.LoadUint32(&g.userCount)
		if v&gateClosed != 0 {
			return false
		}

		if atomic.CompareAndSwapUint32(&g.userCount, v, v+1) {
			return true
		}
	}
}

// Leave leaves the gate. This must only be called after a successful call to
// Enter(). If the gate has been closed and this is the last one inside the
// gate, it will notify the closer that the gate is done.
//
// This function is thread-safe.
func (g *Gate) Leave() {
	for {
		v := atomic.LoadUint32(&g.userCount)
		if v&^gateClosed == 0 {
			panic("leaving a gate with zero usage count")
		}

		if atomic.CompareAndSwapUint32(&g.userCount, v, v-1) {
			if v == gateClosed+1 {
				close(g.done)
			}
			return
		}
	}
}

// Close closes the gate for entering, and waits until all goroutines [that are
// currently inside the gate] leave before returning.
//
// Only one goroutine can call this function.
func (g *Gate) Close() {
	for {
		v := atomic.LoadUint32(&g.userCount)
		if v&^gateClosed != 0 && g.done == nil {
			g.done = make(chan struct{})
		}
		if atomic.CompareAndSwapUint32(&g.userCount, v, v|gateClosed) {
			if v&^gateClosed != 0 {
				<-g.done
			}
			return
		}
	}
}
