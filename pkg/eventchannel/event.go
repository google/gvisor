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

// Package eventchannel contains functionality for sending any protobuf message
// on a socketpair.
//
// The wire format is a uvarint length followed by a binary protobuf.Any
// message.
package eventchannel

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	pb "gvisor.dev/gvisor/pkg/eventchannel/eventchannel_go_proto"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

// Emitter emits a proto message.
type Emitter interface {
	// Emit writes a single eventchannel message to an emitter. Emit should
	// return hangup = true to indicate an emitter has "hung up" and no further
	// messages should be directed to it.
	Emit(msg proto.Message) (hangup bool, err error)

	// Close closes this emitter. Emit cannot be used after Close is called.
	Close() error
}

// DefaultEmitter is the default emitter. Calls to Emit and AddEmitter are sent
// to this Emitter.
var DefaultEmitter = &multiEmitter{}

// Emit is a helper method that calls DefaultEmitter.Emit.
func Emit(msg proto.Message) error {
	_, err := DefaultEmitter.Emit(msg)
	return err
}

// AddEmitter is a helper method that calls DefaultEmitter.AddEmitter.
func AddEmitter(e Emitter) {
	DefaultEmitter.AddEmitter(e)
}

// multiEmitter is an Emitter that forwards messages to multiple Emitters.
type multiEmitter struct {
	// mu protects emitters.
	mu sync.Mutex
	// emitters is initialized lazily in AddEmitter.
	emitters map[Emitter]struct{}
}

// Emit emits a message using all added emitters.
func (me *multiEmitter) Emit(msg proto.Message) (bool, error) {
	me.mu.Lock()
	defer me.mu.Unlock()

	var err error
	for e := range me.emitters {
		hangup, eerr := e.Emit(msg)
		if eerr != nil {
			if err == nil {
				err = fmt.Errorf("error emitting %v: on %v: %v", msg, e, eerr)
			} else {
				err = fmt.Errorf("%v; on %v: %v", err, e, eerr)
			}

			// Log as well, since most callers ignore the error.
			log.Warningf("Error emitting %v on %v: %v", msg, e, eerr)
		}
		if hangup {
			log.Infof("Hangup on eventchannel emitter %v.", e)
			delete(me.emitters, e)
		}
	}

	return false, err
}

// AddEmitter adds a new emitter.
func (me *multiEmitter) AddEmitter(e Emitter) {
	me.mu.Lock()
	defer me.mu.Unlock()
	if me.emitters == nil {
		me.emitters = make(map[Emitter]struct{})
	}
	me.emitters[e] = struct{}{}
}

// Close closes all emitters. If any Close call errors, it returns the first
// one encountered.
func (me *multiEmitter) Close() error {
	me.mu.Lock()
	defer me.mu.Unlock()
	var err error
	for e := range me.emitters {
		if eerr := e.Close(); err == nil && eerr != nil {
			err = eerr
		}
		delete(me.emitters, e)
	}
	return err
}

func marshal(msg proto.Message) ([]byte, error) {
	anypb, err := ptypes.MarshalAny(msg)
	if err != nil {
		return nil, err
	}

	// Wire format is uvarint message length followed by binary proto.
	bufMsg, err := proto.Marshal(anypb)
	if err != nil {
		return nil, err
	}
	p := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(p, uint64(len(bufMsg)))
	return append(p[:n], bufMsg...), nil
}

// socketEmitter emits proto messages on a socket.
type socketEmitter struct {
	socket *unet.Socket
}

// SocketEmitter creates a new event channel based on the given fd.
//
// SocketEmitter takes ownership of fd.
func SocketEmitter(fd int) (Emitter, error) {
	s, err := unet.NewSocket(fd)
	if err != nil {
		return nil, err
	}

	return &socketEmitter{
		socket: s,
	}, nil
}

// Emit implements Emitter.Emit.
func (s *socketEmitter) Emit(msg proto.Message) (bool, error) {
	p, err := marshal(msg)
	if err != nil {
		return false, err
	}
	for done := 0; done < len(p); {
		n, err := s.socket.Write(p[done:])
		if err != nil {
			return (err == syscall.EPIPE), err
		}
		done += n
	}
	return false, nil
}

// Close implements Emitter.Emit.
func (s *socketEmitter) Close() error {
	return s.socket.Close()
}

// debugEmitter wraps an emitter to emit stringified event messages. This is
// useful for debugging -- when the messages are intended for humans.
type debugEmitter struct {
	inner Emitter
}

// DebugEmitterFrom creates a new event channel emitter by wrapping an existing
// raw emitter.
func DebugEmitterFrom(inner Emitter) Emitter {
	return &debugEmitter{
		inner: inner,
	}
}

func (d *debugEmitter) Emit(msg proto.Message) (bool, error) {
	ev := &pb.DebugEvent{
		Name: proto.MessageName(msg),
		Text: proto.MarshalTextString(msg),
	}
	return d.inner.Emit(ev)
}

func (d *debugEmitter) Close() error {
	return d.inner.Close()
}
