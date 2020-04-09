// automatically generated by stateify.

// +build amd64
// +build amd64 arm64

package linux

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *ioEvent) beforeSave() {}
func (x *ioEvent) save(m state.Map) {
	x.beforeSave()
	m.Save("Data", &x.Data)
	m.Save("Obj", &x.Obj)
	m.Save("Result", &x.Result)
	m.Save("Result2", &x.Result2)
}

func (x *ioEvent) afterLoad() {}
func (x *ioEvent) load(m state.Map) {
	m.Load("Data", &x.Data)
	m.Load("Obj", &x.Obj)
	m.Load("Result", &x.Result)
	m.Load("Result2", &x.Result2)
}

func (x *futexWaitRestartBlock) beforeSave() {}
func (x *futexWaitRestartBlock) save(m state.Map) {
	x.beforeSave()
	m.Save("duration", &x.duration)
	m.Save("addr", &x.addr)
	m.Save("private", &x.private)
	m.Save("val", &x.val)
	m.Save("mask", &x.mask)
}

func (x *futexWaitRestartBlock) afterLoad() {}
func (x *futexWaitRestartBlock) load(m state.Map) {
	m.Load("duration", &x.duration)
	m.Load("addr", &x.addr)
	m.Load("private", &x.private)
	m.Load("val", &x.val)
	m.Load("mask", &x.mask)
}

func (x *pollRestartBlock) beforeSave() {}
func (x *pollRestartBlock) save(m state.Map) {
	x.beforeSave()
	m.Save("pfdAddr", &x.pfdAddr)
	m.Save("nfds", &x.nfds)
	m.Save("timeout", &x.timeout)
}

func (x *pollRestartBlock) afterLoad() {}
func (x *pollRestartBlock) load(m state.Map) {
	m.Load("pfdAddr", &x.pfdAddr)
	m.Load("nfds", &x.nfds)
	m.Load("timeout", &x.timeout)
}

func (x *clockNanosleepRestartBlock) beforeSave() {}
func (x *clockNanosleepRestartBlock) save(m state.Map) {
	x.beforeSave()
	m.Save("c", &x.c)
	m.Save("duration", &x.duration)
	m.Save("rem", &x.rem)
}

func (x *clockNanosleepRestartBlock) afterLoad() {}
func (x *clockNanosleepRestartBlock) load(m state.Map) {
	m.Load("c", &x.c)
	m.Load("duration", &x.duration)
	m.Load("rem", &x.rem)
}

func init() {
	state.Register("pkg/sentry/syscalls/linux.ioEvent", (*ioEvent)(nil), state.Fns{Save: (*ioEvent).save, Load: (*ioEvent).load})
	state.Register("pkg/sentry/syscalls/linux.futexWaitRestartBlock", (*futexWaitRestartBlock)(nil), state.Fns{Save: (*futexWaitRestartBlock).save, Load: (*futexWaitRestartBlock).load})
	state.Register("pkg/sentry/syscalls/linux.pollRestartBlock", (*pollRestartBlock)(nil), state.Fns{Save: (*pollRestartBlock).save, Load: (*pollRestartBlock).load})
	state.Register("pkg/sentry/syscalls/linux.clockNanosleepRestartBlock", (*clockNanosleepRestartBlock)(nil), state.Fns{Save: (*clockNanosleepRestartBlock).save, Load: (*clockNanosleepRestartBlock).load})
}
