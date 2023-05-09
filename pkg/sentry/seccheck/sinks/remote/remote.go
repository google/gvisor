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

// Package remote defines a seccheck.Sink that serializes points to a remote
// process. Points are serialized using the protobuf format, asynchronously.
package remote

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

const name = "remote"

func init() {
	seccheck.RegisterSink(seccheck.SinkDesc{
		Name:  name,
		Setup: setupSink,
		New:   new,
	})
}

// remote sends a serialized point to a remote process asynchronously over a
// SOCK_SEQPACKET Unix-domain socket. Each message corresponds to a single
// serialized point proto, preceded by a standard header. If the point cannot
// be sent, e.g. buffer full, the point is dropped on the floor to avoid
// delaying/hanging indefinitely the application.
type remote struct {
	endpoint *fd.FD

	droppedCount atomicbitops.Uint32

	retries        int
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

var _ seccheck.Sink = (*remote)(nil)

// setupSink starts the connection to the remote process and returns a file that
// can be used to communicate with it. The caller is responsible to close to
// file.
func setupSink(config map[string]any) (*os.File, error) {
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

	// Perform handshake. See common.proto for details about the protocol.
	hsOut := pb.Handshake{Version: wire.CurrentVersion}
	out, err := proto.Marshal(&hsOut)
	if err != nil {
		return nil, fmt.Errorf("marshalling handshake message: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		return nil, fmt.Errorf("sending handshake message: %w", err)
	}

	in := make([]byte, 10240)
	read, err := f.Read(in)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading handshake message: %w", err)
	}
	// Protect against the handshake becoming larger than the buffer allocated
	// for it.
	if read == len(in) {
		return nil, fmt.Errorf("handshake message too big")
	}
	hsIn := pb.Handshake{}
	if err := proto.Unmarshal(in[:read], &hsIn); err != nil {
		return nil, fmt.Errorf("unmarshalling handshake message: %w", err)
	}

	// Check that remote version can be supported.
	const minSupportedVersion = 1
	if hsIn.Version < minSupportedVersion {
		return nil, fmt.Errorf("remote version (%d) is smaller than minimum supported (%d)", hsIn.Version, minSupportedVersion)
	}

	if err := unix.SetNonblock(int(f.Fd()), true); err != nil {
		return nil, err
	}

	cu.Release()
	return f, nil
}

func parseDuration(config map[string]any, name string) (bool, time.Duration, error) {
	opaque, ok := config[name]
	if !ok {
		return false, 0, nil
	}
	duration, ok := opaque.(string)
	if !ok {
		return false, 0, fmt.Errorf("%s %v is not an string", name, opaque)
	}
	rv, err := time.ParseDuration(duration)
	if err != nil {
		return false, 0, err
	}
	return true, rv, nil
}

// new creates a new Remote sink.
func new(config map[string]any, endpoint *fd.FD) (seccheck.Sink, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("remote sink requires an endpoint")
	}
	r := &remote{
		endpoint:       endpoint,
		initialBackoff: 25 * time.Microsecond,
		maxBackoff:     10 * time.Millisecond,
	}
	if retriesOpaque, ok := config["retries"]; ok {
		retries, ok := retriesOpaque.(float64)
		if !ok {
			return nil, fmt.Errorf("retries %q is not an int", retriesOpaque)
		}
		r.retries = int(retries)
		if float64(r.retries) != retries {
			return nil, fmt.Errorf("retries %q is not an int", retriesOpaque)
		}
	}
	if ok, backoff, err := parseDuration(config, "backoff"); err != nil {
		return nil, err
	} else if ok {
		r.initialBackoff = backoff
	}
	if ok, backoff, err := parseDuration(config, "backoff_max"); err != nil {
		return nil, err
	} else if ok {
		r.maxBackoff = backoff
	}
	if r.initialBackoff > r.maxBackoff {
		return nil, fmt.Errorf("initial backoff (%v) cannot be larger than max backoff (%v)", r.initialBackoff, r.maxBackoff)
	}

	log.Debugf("Remote sink created, endpoint FD: %d, %+v", r.endpoint.FD(), r)
	return r, nil
}

func (*remote) Name() string {
	return name
}

func (r *remote) Status() seccheck.SinkStatus {
	return seccheck.SinkStatus{
		DroppedCount: uint64(r.droppedCount.Load()),
	}
}

// Stop implements seccheck.Sink.
func (r *remote) Stop() {
	if r.endpoint != nil {
		// It's possible to race with Point firing, but in the worst case they will
		// simply fail to be delivered.
		r.endpoint.Close()
	}
}

func (r *remote) write(msg proto.Message, msgType pb.MessageType) {
	out, err := proto.Marshal(msg)
	if err != nil {
		log.Debugf("Marshal(%+v): %v", msg, err)
		return
	}
	hdr := wire.Header{
		HeaderSize:   uint16(wire.HeaderStructSize),
		DroppedCount: r.droppedCount.Load(),
		MessageType:  uint16(msgType),
	}
	var hdrOut [wire.HeaderStructSize]byte
	hdr.MarshalUnsafe(hdrOut[:])

	backoff := r.initialBackoff
	for i := 0; ; i++ {
		_, err := unix.Writev(r.endpoint.FD(), [][]byte{hdrOut[:], out})
		if err == nil {
			// Write succeeded, we're done!
			return
		}
		if !errors.Is(err, unix.EAGAIN) || i >= r.retries {
			log.Debugf("Write failed, dropping point: %v", err)
			r.droppedCount.Add(1)
			return
		}
		log.Debugf("Write failed, retrying (%d/%d) in %v: %v", i+1, r.retries, backoff, err)
		time.Sleep(backoff)
		backoff *= 2
		if r.maxBackoff > 0 && backoff > r.maxBackoff {
			backoff = r.maxBackoff
		}
	}
}

// Clone implements seccheck.Sink.
func (r *remote) Clone(_ context.Context, _ seccheck.FieldSet, info *pb.CloneInfo) error {
	r.write(info, pb.MessageType_MESSAGE_SENTRY_CLONE)
	return nil
}

// Execve implements seccheck.Sink.
func (r *remote) Execve(_ context.Context, _ seccheck.FieldSet, info *pb.ExecveInfo) error {
	r.write(info, pb.MessageType_MESSAGE_SENTRY_EXEC)
	return nil
}

// ExitNotifyParent implements seccheck.Sink.
func (r *remote) ExitNotifyParent(_ context.Context, _ seccheck.FieldSet, info *pb.ExitNotifyParentInfo) error {
	r.write(info, pb.MessageType_MESSAGE_SENTRY_EXIT_NOTIFY_PARENT)
	return nil
}

// TaskExit implements seccheck.Sink.
func (r *remote) TaskExit(_ context.Context, _ seccheck.FieldSet, info *pb.TaskExit) error {
	r.write(info, pb.MessageType_MESSAGE_SENTRY_TASK_EXIT)
	return nil
}

// ContainerStart implements seccheck.Sink.
func (r *remote) ContainerStart(_ context.Context, _ seccheck.FieldSet, info *pb.Start) error {
	r.write(info, pb.MessageType_MESSAGE_CONTAINER_START)
	return nil
}

// RawSyscall implements seccheck.Sink.
func (r *remote) RawSyscall(_ context.Context, _ seccheck.FieldSet, info *pb.Syscall) error {
	r.write(info, pb.MessageType_MESSAGE_SYSCALL_RAW)
	return nil
}

// Syscall implements seccheck.Sink.
func (r *remote) Syscall(ctx context.Context, fields seccheck.FieldSet, ctxData *pb.ContextData, msgType pb.MessageType, msg proto.Message) error {
	r.write(msg, msgType)
	return nil
}
