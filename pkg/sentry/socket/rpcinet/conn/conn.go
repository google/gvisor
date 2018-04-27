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

// Package conn is an RPC connection to a syscall RPC server.
package conn

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/golang/protobuf/proto"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/unet"

	pb "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/syscall_rpc_go_proto"
)

type request struct {
	response     []byte
	ready        chan struct{}
	ignoreResult bool
}

// RPCConnection represents a single RPC connection to a syscall gofer.
type RPCConnection struct {
	// reqID is the ID of the last request and must be accessed atomically.
	reqID uint64

	sendMu sync.Mutex
	socket *unet.Socket

	reqMu    sync.Mutex
	requests map[uint64]request
}

// NewRPCConnection initializes a RPC connection to a socket gofer.
func NewRPCConnection(s *unet.Socket) *RPCConnection {
	conn := &RPCConnection{socket: s, requests: map[uint64]request{}}
	go func() { // S/R-FIXME
		var nums [16]byte
		for {
			for n := 0; n < len(nums); {
				nn, err := conn.socket.Read(nums[n:])
				if err != nil {
					panic(fmt.Sprint("error reading length from socket rpc gofer: ", err))
				}
				n += nn
			}

			b := make([]byte, binary.LittleEndian.Uint64(nums[:8]))
			id := binary.LittleEndian.Uint64(nums[8:])

			for n := 0; n < len(b); {
				nn, err := conn.socket.Read(b[n:])
				if err != nil {
					panic(fmt.Sprint("error reading request from socket rpc gofer: ", err))
				}
				n += nn
			}

			conn.reqMu.Lock()
			r := conn.requests[id]
			if r.ignoreResult {
				delete(conn.requests, id)
			} else {
				r.response = b
				conn.requests[id] = r
			}
			conn.reqMu.Unlock()
			close(r.ready)
		}
	}()
	return conn
}

// NewRequest makes a request to the RPC gofer and returns the request ID and a
// channel which will be closed once the request completes.
func (c *RPCConnection) NewRequest(req pb.SyscallRequest, ignoreResult bool) (uint64, chan struct{}) {
	b, err := proto.Marshal(&req)
	if err != nil {
		panic(fmt.Sprint("invalid proto: ", err))
	}

	id := atomic.AddUint64(&c.reqID, 1)
	ch := make(chan struct{})

	c.reqMu.Lock()
	c.requests[id] = request{ready: ch, ignoreResult: ignoreResult}
	c.reqMu.Unlock()

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	var nums [16]byte
	binary.LittleEndian.PutUint64(nums[:8], uint64(len(b)))
	binary.LittleEndian.PutUint64(nums[8:], id)
	for n := 0; n < len(nums); {
		nn, err := c.socket.Write(nums[n:])
		if err != nil {
			panic(fmt.Sprint("error writing length and ID to socket gofer: ", err))
		}
		n += nn
	}

	for n := 0; n < len(b); {
		nn, err := c.socket.Write(b[n:])
		if err != nil {
			panic(fmt.Sprint("error writing request to socket gofer: ", err))
		}
		n += nn
	}

	return id, ch
}

// RPCReadFile will execute the ReadFile helper RPC method which avoids the
// common pattern of open(2), read(2), close(2) by doing all three operations
// as a single RPC. It will read the entire file or return EFBIG if the file
// was too large.
func (c *RPCConnection) RPCReadFile(path string) ([]byte, *syserr.Error) {
	req := &pb.SyscallRequest_ReadFile{&pb.ReadFileRequest{
		Path: path,
	}}

	id, ch := c.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-ch

	res := c.Request(id).Result.(*pb.SyscallResponse_ReadFile).ReadFile.Result
	if e, ok := res.(*pb.ReadFileResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.ReadFileResponse_Data).Data, nil
}

// Request retrieves the request corresponding to the given request ID.
//
// The channel returned by NewRequest must have been closed before Request can
// be called. This will happen automatically, do not manually close the
// channel.
func (c *RPCConnection) Request(id uint64) pb.SyscallResponse {
	c.reqMu.Lock()
	r := c.requests[id]
	delete(c.requests, id)
	c.reqMu.Unlock()

	var resp pb.SyscallResponse
	if err := proto.Unmarshal(r.response, &resp); err != nil {
		panic(fmt.Sprint("invalid proto: ", err))
	}

	return resp
}
