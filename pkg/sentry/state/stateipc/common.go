// Copyright 2025 The gVisor Authors.
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

package stateipc

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Everything in this file is an implementation detail and should not be used
// outside of this package. URPC request/response types are exported due to
// URPC limitations.

// OpenRequest is the request type for AsyncFileServer.Open.
type OpenRequest struct {
	// Path is the pathname of the file being opened.
	Path string `json:"path"`

	// Mode is the open mode.
	Mode int `json:"mode"`
}

// Possible values for OpenRequest.Mode:
const (
	// OpenModeInvalid ensures that the zero value for OpenRequest.Mode is invalid.
	OpenModeInvalid = iota

	// OpenModeRead indicates that the file is being opened for reading.
	OpenModeRead

	// OpenModeWrite indicates that the file is being opened for writing.
	OpenModeWrite
)

// OpenResponse is the response type for AsyncFileServer.Open.
type OpenResponse struct {
	// Handle is the handle for the opened server file.
	Handle uint32 `json:"handle"`

	// MaxIOBytes is the maximum number of bytes per read/write request.
	MaxIOBytes uint32 `json:"max_io_bytes"`

	// MaxRanges is the maximum number of file ranges per read/write request.
	MaxRanges uint32 `json:"max_ranges"`

	// MaxParallel is the maximum number of parallel read/write requests.
	MaxParallel uint32 `json:"max_parallel"`

	// FilePayload.Files[0] backs the Flipcall packet window for this file's
	// read/write requests.
	urpc.FilePayload

	// PacketWindowOffset is the offset into FilePayload.Files[0] at which the
	// packet window begins.
	PacketWindowOffset int64 `json:"packet_window_offset"`

	// PacketWindowLength is the length of the packet window backed by
	// FilePayload.Files[0].
	PacketWindowLength int `json:"packet_window_length"`
}

// CloseRequest is the request type for AsyncFileServer.Close.
type CloseRequest struct {
	// Handle is the handle for the opened server file.
	Handle uint32 `json:"handle"`
}

// CloseResponse is the response type for AsyncFileServer.Close.
type CloseResponse struct {
	// empty
}

// RegisterClientFileRequest is the request type for
// AsyncFileServer.RegisterClientFile.
type RegisterClientFileRequest struct {
	// Handle is the handle of the opened server file for which this client
	// file is being registered.
	Handle uint32 `json:"handle"`

	// FilePayload.Files[0] is the file being registered.
	urpc.FilePayload

	// Size is the number of bytes in the file to register.
	Size uint64 `json:"size"`

	// Writable is true if the registered client file must be writable.
	// Writable must be set to true if the server file is opened for reading.
	Writable bool `json:"writable"`

	// Settings configures registered ranges in the file.
	Settings []stateio.ClientFileRangeSetting `json:"settings"`
}

// RegisterClientFileResponse is the response type for
// AsyncFileServer.RegisterClientFile.
type RegisterClientFileResponse struct {
	// Handle is the registered client file handle.
	Handle uint32 `json:"handle"`
}

// The following types are used on per-file Flipcall I/O connections.
//
// For connections serving reads, the datagram sent from client to server
// comprises an readRequestHeader followed by any number of submissions, each
// of which comprises an readSubmissionHeader followed by a variable number of
// FileRanges.
//
// For connections serving writes, the datagram sent from server to client
// comprises a writeRequestHeader followed by any number of submissions, each
// of which comprises a writeSubmissionHeader followed by a variable number of
// FileRanges.
//
// For both reads and writes, the datagram sent from server to client comprises
// an ioResponseHeader followed by any number of ioCompletions. The number of
// submissions and completions is communicated in the "datagram length"
// transmitted and received by flipcall.Endpoint methods.

type readRequestHeader struct {
	// MinCompletions is the minimum number of completions that the server
	// should accumulate before returning control to the client.
	MinCompletions uint32

	// Padding is unused, but aligns the first read submission to 8 bytes.
	Padding uint32
}

type readSubmissionHeader struct {
	// ID is the id passed to AsyncReader.StartRead/Readv.
	ID uint32

	// Padding is unused, but aligns the following field to 8 bytes.
	Padding uint32

	// Offset is the offset into the file being read at which the read begins.
	Offset int64

	// DstHandle is RegisterClientFileResponse.Handle for the file that is the
	// destination of the read.
	DstHandle uint32

	// NumRanges is the number of FileRanges that make up the read's
	// destination.
	NumRanges uint32
}

type writeRequestHeader struct {
	// MinCompletions is the minimum number of completions that the server
	// should accumulate before returning control to the client.
	MinCompletions uint32

	// If Finalize is non-zero, the request corresponds to a call to
	// AsyncWriter.Finalize rather than AsyncWriter.Wait.
	Finalize uint32

	// If Reserve is non-zero, it is the value passed to the most recent call
	// to AsyncWriter.Reserve since the last call to AsyncWriter.Wait.
	Reserve uint64
}

type writeSubmissionHeader struct {
	// ID is the id passed to AsyncWriter.StartWrite/Writev.
	ID uint32

	// SrcHandle is RegisterClientFileResponse.Handle for the file that is the
	// source of the write.
	SrcHandle uint32

	// NumRanges is the number of FileRanges that make up the write's source.
	NumRanges uint32

	// Padding is unused, but aligns following FileRanges to 8 bytes.
	Padding uint32
}

type ioResponseHeader struct {
	// If Errno is non-zero, it is a fatal unix.Errno.
	Errno int32

	// Padding is unused, but aligns the first ioCompletion to 8 bytes.
	Padding uint32
}

type ioCompletion struct {
	// ID is the matching read/writeSubmissionHeader.ID.
	ID uint32

	// N is the number of bytes successfully read or written.
	N uint32

	// If Errno is positive, it is the unix.Errno representing the error that
	// terminated the read or write at N bytes. (Additional details about the
	// error are likely present in the server's logs.) For reads, if Errno is
	// -1, the read terminated at EOF.
	Errno int32
}

// ioErrnoFromError converts an error to an int32 errno communicated via I/O
// Flipcall connection.
func ioErrnoFromError(err error, errKind string) int32 {
	if err == nil {
		return 0
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return -1
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return int32(errno)
	}
	log.Infof("Returning EIO for %s error: %v", errKind, err)
	return int32(unix.EIO)
}

// ioErrorFromErrno converts an int32 errno communicated via I/O Flipcall
// connection to an error.
func ioErrorFromErrno(errno int32, errKind string) error {
	if errno == 0 {
		return nil
	}
	if errno == -1 {
		return io.EOF
	}
	if errno > 0 {
		return unix.Errno(errno)
	}
	return fmt.Errorf("unknown stateipc %s errno %d", errKind, errno)
}
