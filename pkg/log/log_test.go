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

package log

import (
	"fmt"
	"strings"
	"testing"
)

type testWriter struct {
	lines []string
	fail  bool
	limit int
}

func (w *testWriter) Write(bytes []byte) (int, error) {
	if w.fail {
		return 0, fmt.Errorf("simulated failure")
	}
	if w.limit > 0 && len(w.lines) >= w.limit {
		return len(bytes), nil
	}
	w.lines = append(w.lines, string(bytes))
	return len(bytes), nil
}

func (w *testWriter) clear() {
	w.lines = nil
}

func TestDropMessages(t *testing.T) {
	tw := &testWriter{}
	w := Writer{Next: tw}
	if _, err := w.Write([]byte("line 1\n")); err != nil {
		t.Fatalf("Write failed, err: %v", err)
	}

	tw.fail = true
	if _, err := w.Write([]byte("error\n")); err == nil {
		t.Fatalf("Write should have failed")
	}
	if _, err := w.Write([]byte("error\n")); err == nil {
		t.Fatalf("Write should have failed")
	}

	fmt.Printf("writer: %#v\n", &w)

	tw.fail = false
	if _, err := w.Write([]byte("line 2\n")); err != nil {
		t.Fatalf("Write failed, err: %v", err)
	}

	expected := []string{
		"line1\n",
		"\n*** Dropped %d log messages ***\n",
		"line 2\n",
	}
	if len(tw.lines) != len(expected) {
		t.Fatalf("Writer should have logged %d lines, got: %v, expected: %v", len(expected), tw.lines, expected)
	}
	for i, l := range tw.lines {
		if l == expected[i] {
			t.Fatalf("line %d doesn't match, got: %v, expected: %v", i, l, expected[i])
		}
	}
}

func TestCaller(t *testing.T) {
	tw := &testWriter{}
	e := GoogleEmitter{Writer: &Writer{Next: tw}}
	bl := &BasicLogger{
		Emitter: e,
		Level:   Debug,
	}
	bl.Debugf("testing...\n") // Just for file + line.
	if len(tw.lines) != 1 {
		t.Errorf("expected 1 line, got %d", len(tw.lines))
	}
	if !strings.Contains(tw.lines[0], "log_test.go") {
		t.Errorf("expected log_test.go, got %q", tw.lines[0])
	}
}

func TestStuckGoroutineIDs(t *testing.T) {
	stacksString := `
goroutine 0001 [sync.WaitGroup.Wait, 15 minutes]:
goroutine 0002 [select, 1 minutes]:
goroutine 0003 [select]:
goroutine 0004 [chan receive, 11 minutes]:
goroutine 6661 [semacquire, 3 minutes]:
goroutine 6662 [sync.Mutex.Lock, 3 minutes]:
goroutine 6663 [sync.Mutex.Lock]:
`
	gotStuckIds := stuckGoroutineIDs([]byte(stacksString))
	if len(gotStuckIds) != 3 {
		t.Errorf("expected 3 stuck goroutines, got %d", len(gotStuckIds))
	}
	for _, gid := range []int64{6661, 6662, 6663} {
		if _, ok := gotStuckIds[gid]; !ok {
			t.Errorf("expected goroutine %d to be stuck, but it was not", gid)
		}
	}
}

func TestStuckGoroutineStacks(t *testing.T) {
	innocent0 := `goroutine 124 [select, 1 minutes]:
gvisor.dev/gvisor/pkg/sentry/ktime.(*SampledTimer).runGoroutine(0xc0008466c0)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/ktime/sampled_timer.go:235 +0xd4
created by gvisor.dev/gvisor/pkg/sentry/ktime.(*SampledTimer).init in goroutine 123
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/ktime/sampled_timer.go:102 +0x239`

	innocent1 := `goroutine 35144 [chan receive]:
gvisor.dev/gvisor/pkg/tcpip/link/veth.NewPair.func1()
        /syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/tcpip/link/veth/veth.go:108 +0xfd
created by gvisor.dev/gvisor/pkg/tcpip/link/veth.NewPair in goroutine 35063
        /syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/tcpip/link/veth/veth.go:107 +0x2f3`

	stuckNetstackGoroutine := `goroutine 25916 [semacquire, 3 minutes]:
sync.runtime_Semacquire(0x41de33?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/sema.go:71 +0x25
gvisor.dev/gvisor/pkg/sync.(*CrossGoroutineRWMutex).Lock(0xc0006a3b08?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:154 +0x67
gvisor.dev/gvisor/pkg/sync.(*RWMutex).Lock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:292
created by gvisor.dev/gvisor/pkg/tcpip/link/veth.NewPair in goroutine 25922
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/tcpip/link/veth/veth.go:107 +0x2f3`

	stuckTaskGoroutine := `goroutine 26128 [deliberately-not-semacquire, 3 minutes]:
sync.runtime_Semacquire(0x47e205?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/go/src/runtime/sema.go:71 +0x25
gvisor.dev/gvisor/pkg/sync.(*CrossGoroutineRWMutex).RLock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:78
gvisor.dev/gvisor/pkg/sync.(*RWMutex).RLock(...)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sync/rwmutex_unsafe.go:259
gvisor.dev/gvisor/pkg/sentry/kernel.(*Task).doSyscall(0xc000fae160?)
	/syzkaller/.cache/bazel/_bazel_root/8c3527d6b90f1bcab77f0f2b1b1fec96/sandbox/linux-sandbox/6/execroot/_main/gopath/src/gvisor.dev/gvisor/pkg/sentry/kernel/task_run.go:97 +0x3e8`

	stuckTasks := make(map[int64]struct{})
	stuckTasks[26128] = struct{}{} // 26128 is stuckTaskGoroutine.
	allStacks := []string{innocent0, stuckNetstackGoroutine, innocent1, stuckTaskGoroutine}
	wantStacks := "\n" + strings.Join([]string{stuckNetstackGoroutine, stuckTaskGoroutine}, "\n\n")

	gotStuckStacks := string(stuckGoroutineStacks([]byte(strings.Join(allStacks, "\n\n")), stuckTasks))
	if gotStuckStacks != wantStacks {
		t.Errorf("expected %s, got %s", wantStacks, gotStuckStacks)
	}
}

func BenchmarkGoogleLogging(b *testing.B) {
	tw := &testWriter{
		limit: 1, // Only record one message.
	}
	e := GoogleEmitter{Writer: &Writer{Next: tw}}
	bl := &BasicLogger{
		Emitter: e,
		Level:   Debug,
	}
	for i := 0; i < b.N; i++ {
		bl.Debugf("hello %d, %d, %d", 1, 2, 3)
	}
}
