// Copyright 2018 The gVisor Authors.
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

// Package watchdog is responsible for monitoring the sentry for tasks that may
// potentially be stuck or looping inderterminally causing hard to debug hungs in
// the untrusted app.
//
// It works by periodically querying all tasks to check whether they are in user
// mode (RunUser), kernel mode (RunSys), or blocked in the kernel (OffCPU). Tasks
// that have been running in kernel mode for a long time in the same syscall
// without blocking are considered stuck and are reported.
//
// When a stuck task is detected, the watchdog can take one of the following actions:
//		1. LogWarning: Logs a warning message followed by a stack dump of all goroutines.
//			 If a tasks continues to be stuck, the message will repeat every minute, unless
//			 a new stuck task is detected
//		2. Panic: same as above, followed by panic()
//
package watchdog

import (
	"bytes"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sync"
)

// Opts configures the watchdog.
type Opts struct {
	// TaskTimeout is the amount of time to allow a task to execute the
	// same syscall without blocking before it's declared stuck.
	TaskTimeout time.Duration

	// TaskTimeoutAction indicates what action to take when a stuck tasks
	// is detected.
	TaskTimeoutAction Action

	// StartupTimeout is the amount of time to allow between watchdog
	// creation and calling watchdog.Start.
	StartupTimeout time.Duration

	// StartupTimeoutAction indicates what action to take when
	// watchdog.Start is not called within the timeout.
	StartupTimeoutAction Action
}

// DefaultOpts is a default set of options for the watchdog.
var DefaultOpts = Opts{
	// Task timeout.
	TaskTimeout:       3 * time.Minute,
	TaskTimeoutAction: LogWarning,

	// Startup timeout.
	StartupTimeout:       30 * time.Second,
	StartupTimeoutAction: LogWarning,
}

// descheduleThreshold is the amount of time scheduling needs to be off before the entire wait period
// is discounted from task's last update time. It's set high enough that small scheduling delays won't
// trigger it.
const descheduleThreshold = 1 * time.Second

var (
	stuckStartup = metric.MustCreateNewUint64Metric("/watchdog/stuck_startup_detected", true /* sync */, "Incremented once on startup watchdog timeout")
	stuckTasks   = metric.MustCreateNewUint64Metric("/watchdog/stuck_tasks_detected", true /* sync */, "Cumulative count of stuck tasks detected")
)

// Amount of time to wait before dumping the stack to the log again when the same task(s) remains stuck.
var stackDumpSameTaskPeriod = time.Minute

// Action defines what action to take when a stuck task is detected.
type Action int

const (
	// LogWarning logs warning message followed by stack trace.
	LogWarning Action = iota

	// Panic will do the same logging as LogWarning and panic().
	Panic
)

// String returns Action's string representation.
func (a Action) String() string {
	switch a {
	case LogWarning:
		return "LogWarning"
	case Panic:
		return "Panic"
	default:
		panic(fmt.Sprintf("Invalid action: %d", a))
	}
}

// Watchdog is the main watchdog class. It controls a goroutine that periodically
// analyses all tasks and reports if any of them appear to be stuck.
type Watchdog struct {
	// Configuration options are embedded.
	Opts

	// period indicates how often to check all tasks. It's calculated based on
	// opts.TaskTimeout.
	period time.Duration

	// k is where the tasks come from.
	k *kernel.Kernel

	// stop is used to notify to watchdog should stop.
	stop chan struct{}

	// done is used to notify when the watchdog has stopped.
	done chan struct{}

	// offenders map contains all tasks that are currently stuck.
	offenders map[*kernel.Task]*offender

	// lastStackDump tracks the last time a stack dump was generated to prevent
	// spamming the log.
	lastStackDump time.Time

	// lastRun is set to the last time the watchdog executed a monitoring loop.
	lastRun ktime.Time

	// mu protects the fields below.
	mu sync.Mutex

	// running is true if the watchdog is running.
	running bool

	// startCalled is true if Start has ever been called. It remains true
	// even if Stop is called.
	startCalled bool
}

type offender struct {
	lastUpdateTime ktime.Time
}

// New creates a new watchdog.
func New(k *kernel.Kernel, opts Opts) *Watchdog {
	// 4 is arbitrary, just don't want to prolong 'TaskTimeout' too much.
	period := opts.TaskTimeout / 4
	w := &Watchdog{
		Opts:      opts,
		k:         k,
		period:    period,
		offenders: make(map[*kernel.Task]*offender),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}

	// Handle StartupTimeout if it exists.
	if w.StartupTimeout > 0 {
		log.Infof("Watchdog waiting %v for startup", w.StartupTimeout)
		go w.waitForStart() // S/R-SAFE: watchdog is stopped buring save and restarted after restore.
	}

	return w
}

// Start starts the watchdog.
func (w *Watchdog) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.startCalled = true

	if w.running {
		return
	}

	if w.TaskTimeout == 0 {
		log.Infof("Watchdog task timeout disabled")
		return
	}
	w.lastRun = w.k.MonotonicClock().Now()

	log.Infof("Starting watchdog, period: %v, timeout: %v, action: %v", w.period, w.TaskTimeout, w.TaskTimeoutAction)
	go w.loop() // S/R-SAFE: watchdog is stopped during save and restarted after restore.
	w.running = true
}

// Stop requests the watchdog to stop and wait for it.
func (w *Watchdog) Stop() {
	if w.TaskTimeout == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	log.Infof("Stopping watchdog")
	w.stop <- struct{}{}
	<-w.done
	w.running = false
	log.Infof("Watchdog stopped")
}

// waitForStart waits for Start to be called and takes action if it does not
// happen within the startup timeout.
func (w *Watchdog) waitForStart() {
	<-time.After(w.StartupTimeout)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.startCalled {
		// We are fine.
		return
	}

	stuckStartup.Increment()

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Watchdog.Start() not called within %s", w.StartupTimeout))
	w.doAction(w.StartupTimeoutAction, false, &buf)
}

// loop is the main watchdog routine. It only returns when 'Stop()' is called.
func (w *Watchdog) loop() {
	// Loop until someone stops it.
	for {
		select {
		case <-w.stop:
			w.done <- struct{}{}
			return
		case <-time.After(w.period):
			w.runTurn()
		}
	}
}

// runTurn runs a single pass over all tasks and reports anything it finds.
func (w *Watchdog) runTurn() {
	// Someone needs to watch the watchdog. The call below can get stuck if there
	// is a deadlock affecting root's PID namespace mutex. Run it in a goroutine
	// and report if it takes too long to return.
	var tasks []*kernel.Task
	done := make(chan struct{})
	go func() { // S/R-SAFE: watchdog is stopped and restarted during S/R.
		tasks = w.k.TaskSet().Root.Tasks()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(w.TaskTimeout):
		// Report if the watchdog is not making progress.
		// No one is watching the watchdog watcher though.
		w.reportStuckWatchdog()
		<-done
	}

	newOffenders := make(map[*kernel.Task]*offender)
	newTaskFound := false
	now := ktime.FromNanoseconds(int64(w.k.CPUClockNow() * uint64(linux.ClockTick)))

	// The process may be running with low CPU limit making tasks appear stuck because
	// are starved of CPU cycles. An estimate is that Tasks could have been starved
	// since the last time the watchdog run. If the watchdog detects that scheduling
	// is off, it will discount the entire duration since last run from 'lastUpdateTime'.
	discount := time.Duration(0)
	if now.Sub(w.lastRun.Add(w.period)) > descheduleThreshold {
		discount = now.Sub(w.lastRun)
	}
	w.lastRun = now

	log.Infof("Watchdog starting loop, tasks: %d, discount: %v", len(tasks), discount)
	for _, t := range tasks {
		tsched := t.TaskGoroutineSchedInfo()

		// An offender is a task running inside the kernel for longer than the specified timeout.
		if tsched.State == kernel.TaskGoroutineRunningSys {
			lastUpdateTime := ktime.FromNanoseconds(int64(tsched.Timestamp * uint64(linux.ClockTick)))
			elapsed := now.Sub(lastUpdateTime) - discount
			if elapsed > w.TaskTimeout {
				tc, ok := w.offenders[t]
				if !ok {
					// New stuck task detected.
					//
					// Note that tasks blocked doing IO may be considered stuck in kernel,
					// unless they are surrounded b
					// Task.UninterruptibleSleepStart/Finish.
					tc = &offender{lastUpdateTime: lastUpdateTime}
					stuckTasks.Increment()
					newTaskFound = true
				}
				newOffenders[t] = tc
			}
		}
	}
	if len(newOffenders) > 0 {
		w.report(newOffenders, newTaskFound, now)
	}

	// Remember which tasks have been reported.
	w.offenders = newOffenders
}

// report takes appropriate action when a stuck task is detected.
func (w *Watchdog) report(offenders map[*kernel.Task]*offender, newTaskFound bool, now ktime.Time) {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Sentry detected %d stuck task(s):\n", len(offenders)))
	for t, o := range offenders {
		tid := w.k.TaskSet().Root.IDOfTask(t)
		buf.WriteString(fmt.Sprintf("\tTask tid: %v (%#x), entered RunSys state %v ago.\n", tid, uint64(tid), now.Sub(o.lastUpdateTime)))
	}

	buf.WriteString("Search for '(*Task).run(0x..., 0x<tid>)' in the stack dump to find the offending goroutine")

	// Force stack dump only if a new task is detected.
	w.doAction(w.TaskTimeoutAction, newTaskFound, &buf)
}

func (w *Watchdog) reportStuckWatchdog() {
	var buf bytes.Buffer
	buf.WriteString("Watchdog goroutine is stuck")
	w.doAction(w.TaskTimeoutAction, false, &buf)
}

// doAction will take the given action. If the action is LogWarning, the stack
// is not always dumped to the log to prevent log flooding. "forceStack"
// guarantees that the stack will be dumped regardless.
func (w *Watchdog) doAction(action Action, forceStack bool, msg *bytes.Buffer) {
	switch action {
	case LogWarning:
		// Dump stack only if forced or sometime has passed since the last time a
		// stack dump was generated.
		if !forceStack && time.Since(w.lastStackDump) < stackDumpSameTaskPeriod {
			msg.WriteString("\n...[stack dump skipped]...")
			log.Warningf(msg.String())
			return
		}
		log.TracebackAll(msg.String())
		w.lastStackDump = time.Now()

	case Panic:
		// Panic will skip over running tasks, which is likely the culprit here. So manually
		// dump all stacks before panic'ing.
		log.TracebackAll(msg.String())

		// Attempt to flush metrics, timeout and move on in case metrics are stuck as well.
		metricsEmitted := make(chan struct{}, 1)
		go func() { // S/R-SAFE: watchdog is stopped during save and restarted after restore.
			// Flush metrics before killing process.
			metric.EmitMetricUpdate()
			metricsEmitted <- struct{}{}
		}()
		select {
		case <-metricsEmitted:
		case <-time.After(1 * time.Second):
		}
		panic(fmt.Sprintf("%s\nStack for running G's are skipped while panicking.", msg.String()))

	default:
		panic(fmt.Sprintf("Unknown watchdog action %v", action))

	}
}
