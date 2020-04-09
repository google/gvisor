// automatically generated by stateify.

package timerfd

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *TimerOperations) beforeSave() {}
func (x *TimerOperations) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.events) {
		m.Failf("events is %v, expected zero", x.events)
	}
	m.Save("timer", &x.timer)
	m.Save("val", &x.val)
}

func (x *TimerOperations) afterLoad() {}
func (x *TimerOperations) load(m state.Map) {
	m.Load("timer", &x.timer)
	m.Load("val", &x.val)
}

func init() {
	state.Register("pkg/sentry/fs/timerfd.TimerOperations", (*TimerOperations)(nil), state.Fns{Save: (*TimerOperations).save, Load: (*TimerOperations).load})
}
