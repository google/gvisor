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

// Package p9test provides standard mocks for p9.
package p9test

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Harness is an attacher mock.
type Harness struct {
	t            *testing.T
	mockCtrl     *gomock.Controller
	Attacher     *MockAttacher
	wg           sync.WaitGroup
	clientSocket *unet.Socket
	mu           sync.Mutex
	created      []*Mock
}

// globalPath is a QID.Path Generator.
var globalPath atomicbitops.Uint64

// MakePath returns a globally unique path.
func MakePath() uint64 {
	return globalPath.Add(1)
}

// Generator is a function that generates a new file.
type Generator func(parent *Mock) *Mock

// Mock is a common mock element.
type Mock struct {
	p9.DefaultWalkGetAttr
	*MockFile
	parent   *Mock
	closed   bool
	harness  *Harness
	QID      p9.QID
	Attr     p9.Attr
	children map[string]Generator

	// WalkCallback is a special function that will be called from within
	// the walk context. This is needed for the concurrent tests within
	// this package.
	WalkCallback func() error
}

// globalMu protects the children maps in all mocks. Note that this is not a
// particularly elegant solution, but because the test has walks from the root
// through to final nodes, we must share maps below, and it's easiest to simply
// protect against concurrent access globally.
var globalMu sync.RWMutex

// AddChild adds a new child to the Mock.
func (m *Mock) AddChild(name string, generator Generator) {
	globalMu.Lock()
	defer globalMu.Unlock()
	m.children[name] = generator
}

// RemoveChild removes the child with the given name.
func (m *Mock) RemoveChild(name string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	delete(m.children, name)
}

// Matches implements gomock.Matcher.Matches.
func (m *Mock) Matches(x any) bool {
	if om, ok := x.(*Mock); ok {
		return m.QID.Path == om.QID.Path
	}
	return false
}

// String implements gomock.Matcher.String.
func (m *Mock) String() string {
	return fmt.Sprintf("Mock{Mode: 0x%x, QID.Path: %d}", m.Attr.Mode, m.QID.Path)
}

// GetAttr returns the current attributes.
func (m *Mock) GetAttr(mask p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	return m.QID, p9.AttrMaskAll(), m.Attr, nil
}

// Walk supports clone and walking in directories.
func (m *Mock) Walk(names []string) ([]p9.QID, p9.File, error) {
	if m.WalkCallback != nil {
		if err := m.WalkCallback(); err != nil {
			return nil, nil, err
		}
	}
	if len(names) == 0 {
		// Clone the file appropriately.
		nm := m.harness.NewMock(m.parent, m.QID.Path, m.Attr)
		nm.children = m.children // Inherit children.
		return []p9.QID{nm.QID}, nm, nil
	} else if len(names) != 1 {
		m.harness.t.Fail() // Should not happen.
		return nil, nil, unix.EINVAL
	}

	if m.Attr.Mode.IsDir() {
		globalMu.RLock()
		defer globalMu.RUnlock()
		if fn, ok := m.children[names[0]]; ok {
			// Generate the child.
			nm := fn(m)
			return []p9.QID{nm.QID}, nm, nil
		}
		// No child found.
		return nil, nil, unix.ENOENT
	}

	// Call the underlying mock.
	return m.MockFile.Walk(names)
}

// WalkGetAttr calls the default implementation; this is a client-side optimization.
func (m *Mock) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	return m.DefaultWalkGetAttr.WalkGetAttr(names)
}

// Pop pops off the most recently created Mock and assert that this mock
// represents the same file passed in. If nil is passed in, no check is
// performed.
//
// Precondition: there must be at least one Mock or this will panic.
func (h *Harness) Pop(clientFile p9.File) *Mock {
	h.mu.Lock()
	defer h.mu.Unlock()

	if clientFile == nil {
		// If no clientFile is provided, then we always return the last
		// created file. The caller can safely use this as long as
		// there is no concurrency.
		m := h.created[len(h.created)-1]
		h.created = h.created[:len(h.created)-1]
		return m
	}

	qid, _, _, err := clientFile.GetAttr(p9.AttrMaskAll())
	if err != nil {
		// We do not expect this to happen.
		panic(fmt.Sprintf("err during Pop: %v", err))
	}

	// Find the relevant file in our created list. We must scan the last
	// from back to front to ensure that we favor the most recently
	// generated file.
	for i := len(h.created) - 1; i >= 0; i-- {
		m := h.created[i]
		if qid.Path == m.QID.Path {
			// Copy and truncate.
			copy(h.created[i:], h.created[i+1:])
			h.created = h.created[:len(h.created)-1]
			return m
		}
	}

	// Unable to find relevant file.
	panic(fmt.Sprintf("unable to locate file with QID %+v", qid.Path))
}

// NewMock returns a new base file.
func (h *Harness) NewMock(parent *Mock, path uint64, attr p9.Attr) *Mock {
	m := &Mock{
		MockFile: NewMockFile(h.mockCtrl),
		parent:   parent,
		harness:  h,
		QID: p9.QID{
			Type: p9.QIDType((attr.Mode & p9.FileModeMask) >> 12),
			Path: path,
		},
		Attr: attr,
	}

	// Always ensure Close is after the parent's close. Note that this
	// can't be done via a straight-forward After call, because the parent
	// might change after initial creation. We ensure that this is true at
	// close time.
	m.EXPECT().Close().Return(nil).Times(1).Do(func() {
		if m.parent != nil && m.parent.closed {
			h.t.FailNow()
		}
		// Note that this should not be racy, as this operation should
		// be protected by the Times(1) above first.
		m.closed = true
	})

	// Remember what was created.
	h.mu.Lock()
	defer h.mu.Unlock()
	h.created = append(h.created, m)

	return m
}

// NewFile returns a new file mock.
//
// Note that ReadAt and WriteAt must be mocked separately.
func (h *Harness) NewFile() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeRegular})
	}
}

// NewDirectory returns a new mock directory.
//
// Note that Mkdir, Link, Mknod, RenameAt, UnlinkAt and Readdir must be mocked
// separately. Walk is provided and children may be manipulated via AddChild
// and RemoveChild. After calling Walk remotely, one can use Pop to find the
// corresponding backend mock on the server side.
func (h *Harness) NewDirectory(contents map[string]Generator) Generator {
	return func(parent *Mock) *Mock {
		m := h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeDirectory})
		m.children = contents // Save contents.
		return m
	}
}

// NewSymlink returns a new mock directory.
//
// Note that Readlink must be mocked separately.
func (h *Harness) NewSymlink() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeSymlink})
	}
}

// NewBlockDevice returns a new mock block device.
func (h *Harness) NewBlockDevice() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeBlockDevice})
	}
}

// NewCharacterDevice returns a new mock character device.
func (h *Harness) NewCharacterDevice() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeCharacterDevice})
	}
}

// NewNamedPipe returns a new mock named pipe.
func (h *Harness) NewNamedPipe() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeNamedPipe})
	}
}

// NewSocket returns a new mock socket.
func (h *Harness) NewSocket() Generator {
	return func(parent *Mock) *Mock {
		return h.NewMock(parent, MakePath(), p9.Attr{Mode: p9.ModeSocket})
	}
}

// Finish completes all checks and shuts down the server.
func (h *Harness) Finish() {
	h.clientSocket.Shutdown()
	h.wg.Wait()
	h.mockCtrl.Finish()
}

// NewHarness creates and returns a new test server.
//
// It should always be used as:
//
//	h, c := NewHarness(t)
//	defer h.Finish()
func NewHarness(t *testing.T) (*Harness, *p9.Client) {
	// Create the mock.
	mockCtrl := gomock.NewController(t)
	h := &Harness{
		t:        t,
		mockCtrl: mockCtrl,
		Attacher: NewMockAttacher(mockCtrl),
	}

	// Make socket pair.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v wanted nil", err)
	}

	// Start the server, synchronized on exit.
	h.Attacher.EXPECT().ServerOptions().Return(p9.AttacherOptions{}).Times(1)
	server := p9.NewServer(h.Attacher)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		server.Handle(serverSocket)
	}()

	// Create the client.
	client, err := p9.NewClient(clientSocket, p9.DefaultMessageSize, p9.HighestVersionString())
	if err != nil {
		serverSocket.Close()
		clientSocket.Close()
		t.Fatalf("new client got %v, expected nil", err)
		return nil, nil // Never hit.
	}

	// Capture the client socket.
	h.clientSocket = clientSocket
	return h, client
}
