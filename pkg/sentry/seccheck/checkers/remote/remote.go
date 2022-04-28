// Copyright 2021 The gVisor Authors.
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

// Package remote defines a seccheck.Checker that serializes points to a remote
// process. Points are serialized using the protobuf format, asynchronously.
package remote

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/log"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"

	"google.golang.org/protobuf/types/known/anypb"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func init() {
	seccheck.RegisterSink(seccheck.SinkDesc{
		Name:  "remote",
		Setup: Setup,
		New:   New,
	})
}

// Remote sends a serialized point to a remote process asynchronously over a
// SOCK_SEQPACKET Unix-domain socket. Each message corresponds to a single
// serialized point proto, preceded by a standard header. If the point cannot
// be sent, e.g. buffer full, the point is dropped on the floor to avoid
// delaying/hanging indefinitely the application.
type Remote struct {
	seccheck.CheckerDefaults

	endpoint *fd.FD
}

var _ seccheck.Checker = (*Remote)(nil)

// Setup starts the connection to the remote process and returns a file that
// can be used to communicate with it. The caller is responsible to close to
// file.
func Setup(config map[string]interface{}) (*os.File, error) {
	addrOpaque, ok := config["endpoint"]
	if !ok {
		return nil, fmt.Errorf("endpoint not present in configuration")
	}
	addr, ok := addrOpaque.(string)
	if !ok {
		return nil, fmt.Errorf("endpoint %q is not a string", addrOpaque)
	}
	return setup(addr)
}

func setup(path string) (*os.File, error) {
	log.Debugf("Remote sink connecting to %q", path)
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_UNIX, SOCK_SEQPACKET, 0): %w", err)
	}
	f := os.NewFile(uintptr(socket), path)
	cu := cleanup.Make(func() {
		_ = f.Close()
	})
	defer cu.Clean()

	addr := unix.SockaddrUnix{Name: path}
	if err := unix.Connect(int(f.Fd()), &addr); err != nil {
		return nil, fmt.Errorf("connect(%q): %w", path, err)
	}
	cu.Release()
	return f, nil
}

// New creates a new Remote checker.
func New(_ map[string]interface{}, endpoint *fd.FD) (seccheck.Checker, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("remote sink requires an endpoint")
	}
	// TODO(gvisor.dev/issue/4805): perform version handshake with remote:
	//   1. sentry and remote exchange versions
	//	 2. sentry continues if remote >= min(sentry)
	//   3. remote continues if sentry >= min(remote).
	// min() being the minimal supported version. Let's say current sentry
	// supports batching but remote doesn't, sentry can chose to not batch or
	// refuse the connection.
	return &Remote{endpoint: endpoint}, nil
}

// Header is used to describe the message being sent to the remote process.
//
// +marshal
type Header struct {
	// HeaderSize is the size of the header in bytes. The payload comes
	// immediatelly after the header. The length is needed to allow the header to
	// expand in the future without breaking remotes that do not yet understand
	// the new fields.
	HeaderSize uint16
	_          uint16
	// DroppedCount is the number of points that failed to be written and had to
	// be dropped. It wraps around after max(uint32).
	DroppedCount uint32
}

// headerStructSize size of header struct in bytes.
const headerStructSize = 8

// TODO(gvisor.dev/issue/4805) Any requires writing the full type URL to the
// message. We're not memory bandwidth bound, but having an enum event type in
// the header to identify the proto type would reduce message size and speed
// up event dispatch in the consumer.
func (r *Remote) writeAny(any *anypb.Any) error {
	out, err := proto.Marshal(any)
	if err != nil {
		return err
	}
	hdr := Header{
		HeaderSize: uint16(headerStructSize),
	}
	var hdrOut [headerStructSize]byte
	hdr.MarshalUnsafe(hdrOut[:])

	// TODO(gvisor.dev/issue/4805): Change to non-blocking write. Count as dropped
	// if write fails.
	_, err = unix.Writev(r.endpoint.FD(), [][]byte{hdrOut[:], out})
	return err
}

func (r *Remote) write(msg proto.Message) {
	any, err := anypb.New(msg)
	if err != nil {
		log.Debugf("anypd.New(%+v): %v", msg, err)
		return
	}
	if err := r.writeAny(any); err != nil {
		log.Debugf("writeAny(%+v): %v", any, err)
		return
	}
	return
}

// Clone implements seccheck.Checker.
func (r *Remote) Clone(_ context.Context, _ seccheck.FieldSet, info *pb.CloneInfo) error {
	r.write(info)
	return nil
}

// Execve implements seccheck.Checker.
func (r *Remote) Execve(_ context.Context, _ seccheck.FieldSet, info *pb.ExecveInfo) error {
	r.write(info)
	return nil
}

// ExitNotifyParent implements seccheck.Checker.
func (r *Remote) ExitNotifyParent(_ context.Context, _ seccheck.FieldSet, info *pb.ExitNotifyParentInfo) error {
	r.write(info)
	return nil
}

// TaskExit implements seccheck.Checker.
func (r *Remote) TaskExit(_ context.Context, _ seccheck.FieldSet, info *pb.TaskExit) error {
	r.write(info)
	return nil
}

// ContainerStart implements seccheck.Checker.
func (r *Remote) ContainerStart(_ context.Context, _ seccheck.FieldSet, info *pb.Start) error {
	r.write(info)
	return nil
}
