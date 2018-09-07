// Copyright 2018 Google Inc.
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

package p9test

import (
	"io/ioutil"
	"os"
	"reflect"
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

func TestDonateFD(t *testing.T) {
	// Temporary file.
	osFile, err := ioutil.TempFile("", "p9")
	if err != nil {
		t.Fatalf("could not create temporary file: %v", err)
	}
	os.Remove(osFile.Name())

	hfi, err := osFile.Stat()
	if err != nil {
		osFile.Close()
		t.Fatalf("stat failed: %v", err)
	}
	osFileStat := hfi.Sys().(*syscall.Stat_t)

	f, err := fd.NewFromFile(osFile)
	// osFile should always be closed.
	osFile.Close()
	if err != nil {
		t.Fatalf("unable to create file: %v", err)
	}

	// Craft attacher to attach to the mocked file which will return our
	// temporary file.
	fileMock := &FileMock{
		OpenMock: OpenMock{File: f},
		GetAttrMock: GetAttrMock{
			// The mode must be valid always.
			Valid: p9.AttrMask{Mode: true},
		},
	}
	attacher := &AttachMock{
		File: fileMock,
	}

	// Make socket pair.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v wanted nil", err)
	}
	defer clientSocket.Close()
	server := p9.NewServer(attacher)
	go server.Handle(serverSocket)
	client, err := p9.NewClient(clientSocket, 1024*1024 /* 1M message size */, p9.HighestVersionString())
	if err != nil {
		t.Fatalf("new client got %v, expected nil", err)
	}

	// Attach to the mocked file.
	cFile, err := client.Attach("")
	if err != nil {
		t.Fatalf("attach failed: %v", err)
	}

	// Try to open the mocked file.
	clientHostFile, _, _, err := cFile.Open(0)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	var clientStat syscall.Stat_t
	if err := syscall.Fstat(clientHostFile.FD(), &clientStat); err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	// Compare inode nums to make sure it's the same file.
	if clientStat.Ino != osFileStat.Ino {
		t.Errorf("fd donation failed")
	}
}

// TestClient is a megatest.
//
// This allows us to probe various edge cases, while changing the state of the
// underlying server in expected ways. The test slowly builds server state and
// is documented inline.
//
// We wind up with the following, after probing edge cases:
//
// FID 1: ServerFile (sf).
// FID 2: Directory (d).
// FID 3: File (f).
// FID 4: Symlink (s).
//
// Although you should use the FID method on the individual files.
func TestClient(t *testing.T) {
	var (
		// Sentinel error.
		sentinelErr = syscall.Errno(4383)

		// Backend mocks.
		a  = &AttachMock{}
		sf = &FileMock{}
		d  = &FileMock{}
		f  = &FileMock{}
		s  = &FileMock{}

		// Client Files for the above.
		sfFile p9.File
	)

	testSteps := []struct {
		name string
		fn   func(*p9.Client) error
		want error
	}{
		{
			name: "bad-attach",
			want: sentinelErr,
			fn: func(c *p9.Client) error {
				a.File = nil
				a.Err = sentinelErr
				_, err := c.Attach("")
				return err
			},
		},
		{
			name: "attach",
			fn: func(c *p9.Client) error {
				a.Called = false
				a.File = sf
				a.Err = nil
				// The attached root must have a valid mode.
				sf.GetAttrMock.Attr = p9.Attr{Mode: p9.ModeDirectory}
				sf.GetAttrMock.Valid = p9.AttrMask{Mode: true}
				var err error
				sfFile, err = c.Attach("")
				if !a.Called {
					t.Errorf("Attach never Called?")
				}
				return err
			},
		},
		{
			name: "bad-walk",
			want: sentinelErr,
			fn: func(c *p9.Client) error {
				// Walk only called when WalkGetAttr not available.
				sf.WalkGetAttrMock.Err = syscall.ENOSYS
				sf.WalkMock.File = d
				sf.WalkMock.Err = sentinelErr
				_, _, err := sfFile.Walk([]string{"foo", "bar"})
				return err
			},
		},
		{
			name: "walk-to-dir",
			fn: func(c *p9.Client) error {
				// Walk only called when WalkGetAttr not available.
				sf.WalkGetAttrMock.Err = syscall.ENOSYS
				sf.WalkMock.Called = false
				sf.WalkMock.Names = nil
				sf.WalkMock.File = d
				sf.WalkMock.Err = nil
				sf.WalkMock.QIDs = []p9.QID{{Type: 1}}
				// All intermediate values must be directories.
				d.WalkGetAttrMock.Err = syscall.ENOSYS
				d.WalkMock.Called = false
				d.WalkMock.Names = nil
				d.WalkMock.File = d // Walk to self.
				d.WalkMock.Err = nil
				d.WalkMock.QIDs = []p9.QID{{Type: 1}}
				d.GetAttrMock.Attr = p9.Attr{Mode: p9.ModeDirectory}
				d.GetAttrMock.Valid = p9.AttrMask{Mode: true}
				var qids []p9.QID
				var err error
				qids, _, err = sfFile.Walk([]string{"foo", "bar"})
				if !sf.WalkMock.Called {
					t.Errorf("Walk never Called?")
				}
				if !d.GetAttrMock.Called {
					t.Errorf("GetAttr never Called?")
				}
				if !reflect.DeepEqual(sf.WalkMock.Names, []string{"foo"}) {
					t.Errorf("got names %v wanted []{foo}", sf.WalkMock.Names)
				}
				if !reflect.DeepEqual(d.WalkMock.Names, []string{"bar"}) {
					t.Errorf("got names %v wanted []{bar}", d.WalkMock.Names)
				}
				if len(qids) != 2 || qids[len(qids)-1].Type != 1 {
					t.Errorf("got qids %v wanted []{..., {Type: 1}}", qids)
				}
				return err
			},
		},
		{
			name: "walkgetattr-to-dir",
			fn: func(c *p9.Client) error {
				sf.WalkGetAttrMock.Called = false
				sf.WalkGetAttrMock.Names = nil
				sf.WalkGetAttrMock.File = d
				sf.WalkGetAttrMock.Err = nil
				sf.WalkGetAttrMock.QIDs = []p9.QID{{Type: 1}}
				sf.WalkGetAttrMock.Attr = p9.Attr{Mode: p9.ModeDirectory, UID: 1}
				sf.WalkGetAttrMock.Valid = p9.AttrMask{Mode: true}
				// See above.
				d.WalkGetAttrMock.Called = false
				d.WalkGetAttrMock.Names = nil
				d.WalkGetAttrMock.File = d // Walk to self.
				d.WalkGetAttrMock.Err = nil
				d.WalkGetAttrMock.QIDs = []p9.QID{{Type: 1}}
				d.WalkGetAttrMock.Attr = p9.Attr{Mode: p9.ModeDirectory, UID: 1}
				d.WalkGetAttrMock.Valid = p9.AttrMask{Mode: true}
				var qids []p9.QID
				var err error
				var mask p9.AttrMask
				var attr p9.Attr
				qids, _, mask, attr, err = sfFile.WalkGetAttr([]string{"foo", "bar"})
				if !sf.WalkGetAttrMock.Called {
					t.Errorf("Walk never Called?")
				}
				if !reflect.DeepEqual(sf.WalkGetAttrMock.Names, []string{"foo"}) {
					t.Errorf("got names %v wanted []{foo}", sf.WalkGetAttrMock.Names)
				}
				if !reflect.DeepEqual(d.WalkGetAttrMock.Names, []string{"bar"}) {
					t.Errorf("got names %v wanted []{bar}", d.WalkGetAttrMock.Names)
				}
				if len(qids) != 2 || qids[len(qids)-1].Type != 1 {
					t.Errorf("got qids %v wanted []{..., {Type: 1}}", qids)
				}
				if !reflect.DeepEqual(attr, sf.WalkGetAttrMock.Attr) {
					t.Errorf("got attrs %s wanted %s", attr, sf.WalkGetAttrMock.Attr)
				}
				if !reflect.DeepEqual(mask, sf.WalkGetAttrMock.Valid) {
					t.Errorf("got mask %s wanted %s", mask, sf.WalkGetAttrMock.Valid)
				}
				return err
			},
		},
		{
			name: "walk-to-file",
			fn: func(c *p9.Client) error {
				// Basic sanity check is done in walk-to-dir.
				//
				// Here we just create basic file FIDs to use.
				sf.WalkMock.File = f
				sf.WalkMock.Err = nil
				var err error
				_, _, err = sfFile.Walk(nil)
				return err
			},
		},
		{
			name: "walk-to-symlink",
			fn: func(c *p9.Client) error {
				// See note in walk-to-file.
				sf.WalkMock.File = s
				sf.WalkMock.Err = nil
				var err error
				_, _, err = sfFile.Walk(nil)
				return err
			},
		},
		{
			name: "bad-statfs",
			want: sentinelErr,
			fn: func(c *p9.Client) error {
				sf.StatFSMock.Err = sentinelErr
				_, err := sfFile.StatFS()
				return err
			},
		},
		{
			name: "statfs",
			fn: func(c *p9.Client) error {
				sf.StatFSMock.Called = false
				sf.StatFSMock.Stat = p9.FSStat{Type: 1}
				sf.StatFSMock.Err = nil
				stat, err := sfFile.StatFS()
				if !sf.StatFSMock.Called {
					t.Errorf("StatfS never Called?")
				}
				if stat.Type != 1 {
					t.Errorf("got stat %v wanted {Type: 1}", stat)
				}
				return err
			},
		},
	}

	// First, create a new server and connection.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v wanted nil", err)
	}
	defer clientSocket.Close()
	server := p9.NewServer(a)
	go server.Handle(serverSocket)
	client, err := p9.NewClient(clientSocket, 1024*1024 /* 1M message size */, p9.HighestVersionString())
	if err != nil {
		t.Fatalf("new client got err %v, wanted nil", err)
	}

	// Now, run through each of the test steps.
	for _, step := range testSteps {
		err := step.fn(client)
		if err != step.want {
			// Don't fail, just note this one step failed.
			t.Errorf("step %q got %v wanted %v", step.name, err, step.want)
		}
	}
}

func BenchmarkClient(b *testing.B) {
	// Backend mock.
	a := &AttachMock{
		File: &FileMock{
			ReadAtMock: ReadAtMock{N: 1},
		},
	}

	// First, create a new server and connection.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		b.Fatalf("socketpair got err %v wanted nil", err)
	}
	defer clientSocket.Close()
	server := p9.NewServer(a)
	go server.Handle(serverSocket)
	client, err := p9.NewClient(clientSocket, 1024*1024 /* 1M message size */, p9.HighestVersionString())
	if err != nil {
		b.Fatalf("new client got %v, expected nil", err)
	}

	// Attach to the server.
	f, err := client.Attach("")
	if err != nil {
		b.Fatalf("error during attach, got %v wanted nil", err)
	}

	// Open the file.
	if _, _, _, err := f.Open(p9.ReadOnly); err != nil {
		b.Fatalf("error during open, got %v wanted nil", err)
	}

	// Reset the clock.
	b.ResetTimer()

	// Do N reads.
	var buf [1]byte
	for i := 0; i < b.N; i++ {
		_, err := f.ReadAt(buf[:], 0)
		if err != nil {
			b.Fatalf("error during read %d, got %v wanted nil", i, err)
		}
	}
}
