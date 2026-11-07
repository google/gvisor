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
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

type recordingStack struct {
	*TestStack
	name             string
	preserveLoopback bool
	destroyed        bool
	events           *[]string
}

func (s *recordingStack) PreserveLoopback() {
	s.preserveLoopback = true
}

func (s *recordingStack) Destroy() {
	s.destroyed = true
	*s.events = append(*s.events, "destroy:"+s.name)
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

func (s *recordingStack) StartTransportProtocols() {
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
	grandchild := NewNamespace(child1, userNS)
	child2 := NewNamespace(rootNS, userNS)

	if rootStack.preserveLoopback {
		t.Errorf("rootStack.preserveLoopback = true, want false")
	}
	for _, tc := range []struct {
		name string
		ns   *Namespace
	}{
		{name: "child1", ns: child1},
		{name: "grandchild", ns: grandchild},
		{name: "child2", ns: child2},
	} {
		s := tc.ns.Stack().(*recordingStack)
		if !s.preserveLoopback {
			t.Errorf("%s.preserveLoopback = false, want true", tc.name)
		}
	}

	rootNS.PauseStacks()
	rootNS.ResumeStacks()
	wantAllStacksEvents := []string{
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
		t.Fatalf("PauseStacks/ResumeStacks events mismatch (-want +got):\n%s", diff)
	}

	events = nil
	child1.Destroy(context.Background())
	if !child1.Stack().(*recordingStack).destroyed {
		t.Fatalf("child1 stack destroyed = false, want true")
	}

	rootNS.RestoreStacks()
	wantRestoreEvents := []string{
		"destroy:child1",
		"phase1:root",
		"phase1:grandchild",
		"phase1:child2",
		"phase2:root",
		"phase2:grandchild",
		"phase2:child2",
	}
	if diff := cmp.Diff(wantRestoreEvents, events); diff != "" {
		t.Fatalf("Destroy/RestoreStacks events mismatch (-want +got):\n%s", diff)
	}
}
