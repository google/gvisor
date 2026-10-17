// Copyright 2026 The gVisor Authors.
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

package inet

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/state"
)

type recordingStack struct {
	*TestStack
	name        string
	destroyed   bool
	asyncBlock  chan struct{}
	asyncExited chan struct{}
	events      *[]string
}

func (s *recordingStack) Destroy() {
	s.destroyed = true
	*s.events = append(*s.events, "destroy:"+s.name)
}

func (s *recordingStack) DestroyAsync(done func()) {
	s.destroyed = true
	if s.asyncBlock == nil {
		*s.events = append(*s.events, "destroy:"+s.name)
		if done != nil {
			done()
		}
		return
	}
	go func() {
		<-s.asyncBlock
		*s.events = append(*s.events, "asyncDestroyDone:"+s.name)
		if done != nil {
			done()
		}
		if s.asyncExited != nil {
			close(s.asyncExited)
		}
	}()
}

func (s *recordingStack) Pause() {
	*s.events = append(*s.events, "pause:"+s.name)
}

func (s *recordingStack) Resume() {
	*s.events = append(*s.events, "resume:"+s.name)
}

func (s *recordingStack) SetRemoveConf(removeConf bool) {
	*s.events = append(*s.events, fmt.Sprintf("removeConf:%s:%t", s.name, removeConf))
}

func (s *recordingStack) RestoreNICsAndEndpoints() {
	*s.events = append(*s.events, "phase1:"+s.name)
}

func (s *recordingStack) RestoreBackgroundWorkers() {
	*s.events = append(*s.events, "phase2:"+s.name)
}

type recordingStackCreator struct {
	names  []string
	events *[]string
}

func (c *recordingStackCreator) CreateStack() (Stack, error) {
	name := c.names[0]
	c.names = c.names[1:]
	return &recordingStack{
		TestStack: NewTestStack(),
		name:      name,
		events:    c.events,
	}, nil
}

func TestNamespaceChildTrackingAndRestoreStacksOrder(t *testing.T) {
	userNS := auth.NewRootUserNamespace()
	var events []string
	rootStack := &recordingStack{
		TestStack: NewTestStack(),
		name:      "root",
		events:    &events,
	}
	creator := &recordingStackCreator{
		names:  []string{"child1", "grandchild", "child2"},
		events: &events,
	}

	rootNS := NewRootNamespace(rootStack, creator, userNS)
	child1 := NewNamespace(rootNS, userNS)
	NewNamespace(child1, userNS)
	NewNamespace(rootNS, userNS)

	rootNS.SetRemoveConfStacks(true)
	rootNS.PauseStacks()
	rootNS.ResumeStacks()
	wantAllStacksEvents := []string{
		"removeConf:root:true",
		"removeConf:child1:true",
		"removeConf:grandchild:true",
		"removeConf:child2:true",
		"pause:root",
		"pause:child1",
		"pause:grandchild",
		"pause:child2",
		"resume:root",
		"resume:child1",
		"resume:grandchild",
		"resume:child2",
	}
	if diff := cmp.Diff(wantAllStacksEvents, events); diff != "" {
		t.Fatalf("SetRemoveConfStacks/PauseStacks/ResumeStacks events mismatch (-want +got):\n%s", diff)
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("child1.PauseStacks() did not panic on non-root namespace")
			}
		}()
		child1.PauseStacks()
	}()

	// Verify PauseStacks waits for in-flight asynchronous child stack teardown
	// before pausing remaining stacks.
	events = nil
	child1Stack := child1.Stack().(*recordingStack)
	child1Stack.asyncBlock = make(chan struct{})
	child1Stack.asyncExited = make(chan struct{})
	child1.Destroy(context.Background())
	if !child1Stack.destroyed {
		t.Fatalf("child1 stack destroyed = false, want true")
	}

	pauseDone := make(chan struct{})
	go func() {
		rootNS.PauseStacks()
		close(pauseDone)
	}()
	select {
	case <-pauseDone:
		t.Fatal("PauseStacks returned before child1 async destroy completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(child1Stack.asyncBlock)
	<-pauseDone
	<-child1Stack.asyncExited

	wantAsyncPauseEvents := []string{
		"asyncDestroyDone:child1",
		"pause:root",
		"pause:grandchild",
		"pause:child2",
	}
	if diff := cmp.Diff(wantAsyncPauseEvents, events); diff != "" {
		t.Fatalf("async Destroy/PauseStacks events mismatch (-want +got):\n%s", diff)
	}

	events = nil
	rootNS.RestoreStacks()
	wantRestoreEvents := []string{
		"phase1:root",
		"phase1:grandchild",
		"phase1:child2",
		"phase2:root",
		"phase2:grandchild",
		"phase2:child2",
	}
	if diff := cmp.Diff(wantRestoreEvents, events); diff != "" {
		t.Fatalf("RestoreStacks events mismatch (-want +got):\n%s", diff)
	}
}

func TestNamespaceSaveLoadRoundTrip(t *testing.T) {
	userNS := auth.NewRootUserNamespace()
	rootNS := NewRootNamespace(nil, nil, userNS)
	child1 := NewNamespace(rootNS, userNS)
	grandchild := NewNamespace(child1, userNS)
	child2 := NewNamespace(rootNS, userNS)
	child1.Destroy(context.Background())

	saved := [3]*Namespace{rootNS, grandchild, child2}
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &saved); err != nil {
		t.Fatalf("state.Save failed: %v", err)
	}

	var loaded [3]*Namespace
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load failed: %v", err)
	}
	loadedRoot, loadedGrandchild, loadedChild2 := loaded[0], loaded[1], loaded[2]
	if !loadedRoot.IsRoot() {
		t.Errorf("loadedRoot.IsRoot() = false, want true")
	}
	if loadedGrandchild.root != loadedRoot {
		t.Errorf("loadedGrandchild.root = %p, want %p", loadedGrandchild.root, loadedRoot)
	}
	if loadedChild2.root != loadedRoot {
		t.Errorf("loadedChild2.root = %p, want %p", loadedChild2.root, loadedRoot)
	}

	var events []string
	loadedRoot.RestoreRootStack(&recordingStack{TestStack: NewTestStack(), name: "root", events: &events})
	loadedGrandchild.stack = &recordingStack{TestStack: NewTestStack(), name: "grandchild", events: &events}
	loadedChild2.stack = &recordingStack{TestStack: NewTestStack(), name: "child2", events: &events}

	loadedRoot.RestoreStacks()
	wantEvents := []string{
		"phase1:root",
		"phase1:grandchild",
		"phase1:child2",
		"phase2:root",
		"phase2:grandchild",
		"phase2:child2",
	}
	if diff := cmp.Diff(wantEvents, events); diff != "" {
		t.Fatalf("loadedRoot.RestoreStacks() events mismatch (-want +got):\n%s", diff)
	}
}
