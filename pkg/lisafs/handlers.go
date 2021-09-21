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

package lisafs

import (
	"path"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// RPCHandler defines a handler that is invoked when the associated message is
// received. The handler is responsible for:
//
// * Unmarshalling the request from the passed payload and interpreting it.
// * Marshalling the response into the communicator's payload buffer.
// * Return the number of payload bytes written.
// * Donate any FDs (if needed) to comm which will in turn donate it to client.
type RPCHandler func(c *Connection, comm Communicator, payloadLen uint32) (uint32, error)

var handlers = [...]RPCHandler{
	Error:   ErrorHandler,
	Mount:   MountHandler,
	Channel: ChannelHandler,
}

// ErrorHandler handles Error message.
func ErrorHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	// Client should never send Error.
	return 0, unix.EINVAL
}

// MountHandler handles the Mount RPC. Note that there can not be concurrent
// executions of MountHandler on a connection because the connection enforces
// that Mount is the first message on the connection. Only after the connection
// has been successfully mounted can other channels be created.
func MountHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	var req MountReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	mountPath := path.Clean(string(req.MountPath))
	if !filepath.IsAbs(mountPath) {
		log.Warningf("mountPath %q is not absolute", mountPath)
		return 0, unix.EINVAL
	}

	if c.mounted {
		log.Warningf("connection has already been mounted at %q", mountPath)
		return 0, unix.EBUSY
	}

	rootFD, rootIno, err := c.ServerImpl().Mount(c, mountPath)
	if err != nil {
		return 0, err
	}

	c.server.addMountPoint(rootFD.FD())
	c.mounted = true
	resp := MountResp{
		Root:           rootIno,
		SupportedMs:    c.ServerImpl().SupportedMessages(),
		MaxMessageSize: primitive.Uint32(c.ServerImpl().MaxMessageSize()),
	}
	respPayloadLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respPayloadLen))
	return respPayloadLen, nil
}

// ChannelHandler handles the Channel RPC.
func ChannelHandler(c *Connection, comm Communicator, payloadLen uint32) (uint32, error) {
	ch, desc, fdSock, err := c.createChannel(c.ServerImpl().MaxMessageSize())
	if err != nil {
		return 0, err
	}

	// Start servicing the channel in a separate goroutine.
	c.activeWg.Add(1)
	go func() {
		if err := c.service(ch); err != nil {
			// Don't log shutdown error which is expected during server shutdown.
			if _, ok := err.(flipcall.ShutdownError); !ok {
				log.Warningf("lisafs.Connection.service(channel = @%p): %v", ch, err)
			}
		}
		c.activeWg.Done()
	}()

	clientDataFD, err := unix.Dup(desc.FD)
	if err != nil {
		unix.Close(fdSock)
		ch.shutdown()
		return 0, err
	}

	// Respond to client with successful channel creation message.
	if err := comm.DonateFD(clientDataFD); err != nil {
		return 0, err
	}
	if err := comm.DonateFD(fdSock); err != nil {
		return 0, err
	}
	resp := ChannelResp{
		dataOffset: desc.Offset,
		dataLength: uint64(desc.Length),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}
