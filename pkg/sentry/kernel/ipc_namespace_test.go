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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/msgqueue"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

func TestIPCNamespaceMsgqueueRemovePermissions(t *testing.T) {
	ctx := contexttest.Context(t)
	defer pgalloc.MemoryFileFromContext(ctx).Destroy()
	owner := auth.CredentialsFromContext(ctx)

	ns := NewIPCNamespace(owner.UserNamespace)
	// The namespace has no nsfs inode, so destroy it directly.
	defer ns.Destroy(ctx)
	registry := ns.MsgqueueRegistry()
	queue, err := registry.FindOrCreate(ctx, linux.IPC_PRIVATE, 0600, true, true, false)
	if err != nil {
		t.Fatalf("FindOrCreate: %v", err)
	}
	id := queue.ID()

	const text = "preserved"
	if err := queue.Send(ctx, msgqueue.Message{Type: 1, Text: []byte(text)}, false /* wait */, 123); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// contexttest supplies UID 65534. UID 1 is not the owner and has no
	// effective capabilities.
	other := auth.NewUserCredentials(1, 1, nil, nil, owner.UserNamespace)
	if err := registry.Remove(id, other); err != linuxerr.EPERM {
		t.Errorf("Remove by non-owner = %v, want EPERM", err)
	}
	if got, err := registry.FindByID(id); err != nil || got != queue {
		t.Fatalf("FindByID after denied removal = (%p, %v), want (%p, nil)", got, err, queue)
	}
	message, err := queue.Receive(ctx, 0, uint64(len(text)), linux.IPC_NOWAIT, 123)
	if err != nil {
		t.Fatalf("Receive after denied removal: %v", err)
	}
	if message.Type != 1 || string(message.Text) != text {
		t.Errorf("Receive after denied removal = (%d, %q), want (1, %q)", message.Type, message.Text, text)
	}
	if err := registry.Remove(id, owner); err != nil {
		t.Fatalf("Remove by owner: %v", err)
	}
	if err := registry.Remove(id, owner); err != linuxerr.EINVAL {
		t.Errorf("Remove after removal = %v, want EINVAL", err)
	}
}
