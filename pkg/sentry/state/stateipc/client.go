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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
)

// AsyncFileClient provides async I/O by communicating with an AsyncFileServer,
// which may be in another process.
type AsyncFileClient struct {
	asyncFileClientRefs

	filesMu sync.Mutex
	files   map[*asyncReadWriter]struct{}

	uc           *urpc.Client
	watchdog     sync.WaitGroup
	watchdogStop eventfd.Eventfd
}

// NewAsyncFileClient returns an AsyncFileClient that communicates with an
// AsyncFileServer using uc, with one reference held by the caller. It takes
// ownership of uc, even if it returns a non-nil error.
func NewAsyncFileClient(uc *urpc.Client) (*AsyncFileClient, error) {
	watchdogStop, err := eventfd.Create()
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("failed to create watchdog eventfd: %w", err)
	}
	c := &AsyncFileClient{
		files:        make(map[*asyncReadWriter]struct{}),
		uc:           uc,
		watchdogStop: watchdogStop,
	}
	c.asyncFileClientRefs.InitRefs()
	c.watchdog.Add(1)
	go c.watchdogMain()
	return c, nil
}

// watchdogMain is the main function of the watchdog goroutine, which shuts
// down Flipcall endpoints if c.uc.Socket is disconnected.
func (c *AsyncFileClient) watchdogMain() {
	defer c.watchdog.Done()
	events := []unix.PollFd{
		{
			Fd:     int32(c.watchdogStop.FD()),
			Events: unix.POLLIN,
		},
		{
			Fd:     int32(c.uc.Socket.FD()),
			Events: unix.POLLHUP | unix.POLLRDHUP,
		},
	}
	for {
		_, err := unix.Ppoll(events, nil, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			panic(fmt.Sprintf("stateipc.AsyncFileClient: watchdog got ppoll error: %v", err))
		}
		if events[0].Revents != 0 {
			return
		}
		if events[1].Revents != 0 {
			log.Infof("stateipc.AsyncFileClient: socket disconnected, shutting down file connections")
			c.filesMu.Lock()
			defer c.filesMu.Unlock()
			for rw := range c.files {
				if !rw.destroyed {
					rw.ioep.Shutdown()
				}
			}
			return
		}
	}
}

// DecRef decrements c's reference count.
func (c *AsyncFileClient) DecRef() {
	c.asyncFileClientRefs.DecRef(func() {
		// Note that since each asyncReadWriter holds a reference on c, if c
		// has reached 0 references, there are no asyncReadWriters that need to
		// be shut down.
		if err := c.watchdogStop.Notify(); err != nil {
			// This is unexpected, but probably not panic-worthy since the
			// watchdog should still stop (but with a spurious disconnection
			// warning) after c.uc.Close() below.
			log.Warningf("stateipc.AsyncFileClient: failed to stop watchdog: %v", err)
		} else {
			c.watchdog.Wait()
		}
		c.watchdogStop.Close()
		c.uc.Close()
	})
}

// OpenRead opens the given file for reading. If it succeeds, the returned
// AsyncReader holds a reference on the AsyncFileClient.
func (c *AsyncFileClient) OpenRead(path string) (stateio.AsyncReader, error) {
	return c.open(path, OpenModeRead)
}

// OpenWrite opens the given file for writing. If it succeeds, the returned
// AsyncWriter holds a reference on the AsyncFileClient.
func (c *AsyncFileClient) OpenWrite(path string) (stateio.AsyncWriter, error) {
	return c.open(path, OpenModeWrite)
}

func (c *AsyncFileClient) open(path string, mode int) (*asyncReadWriter, error) {
	c.filesMu.Lock()
	defer c.filesMu.Unlock()
	req := OpenRequest{
		Path: path,
		Mode: mode,
	}
	var resp OpenResponse
	if err := c.uc.Call("AsyncFileServer.Open", &req, &resp); err != nil {
		return nil, err
	}
	if got := len(resp.FilePayload.Files); got != 1 {
		for _, file := range resp.FilePayload.Files {
			file.Close()
		}
		return nil, fmt.Errorf("got %d file descriptors, expected 1", got)
	}
	// The packet window FD isn't needed after it's been mapped.
	pwFD := resp.FilePayload.Files[0].Fd()
	defer resp.FilePayload.Files[0].Close()
	rw := &asyncReadWriter{
		client:      c,
		maxIOBytes:  resp.MaxIOBytes,
		maxRanges:   resp.MaxRanges,
		maxParallel: resp.MaxParallel,
		handle:      resp.Handle,
		isReader:    mode == OpenModeRead,
	}
	if err := rw.ioep.Init(flipcall.ClientSide, flipcall.PacketWindowDescriptor{
		FD:     int(pwFD),
		Offset: resp.PacketWindowOffset,
		Length: resp.PacketWindowLength,
	}); err != nil {
		rw.closeWithoutEndpoint()
		return nil, fmt.Errorf("failed to initialize client flipcall endpoint: %w", err)
	}
	rw.connectorWG.Add(1)
	go func() {
		defer rw.connectorWG.Done()
		rw.ensureConnected()
	}()
	c.files[rw] = struct{}{}
	c.IncRef()
	return rw, nil
}

// asyncReadWriter implements stateio.AsyncReader and stateio.AsyncWriter by
// reading from, or writing to, a file provided by an AsyncFileServer.
//
// Any given asyncReadWriter functions either as an AsyncReader or an
// AsyncWriter, never both at the same time.
type asyncReadWriter struct {
	// Immutable fields:
	client      *AsyncFileClient
	maxIOBytes  uint32
	maxRanges   uint32
	maxParallel uint32
	handle      uint32
	isReader    bool

	// destroyed is true if ioep.Destroy() has been called. destroyed
	// is protected by client.filesMu.
	destroyed bool

	// numSubmissions is the number of submissions to be sent to the server by
	// the next call to Wait().
	numSubmissions uint32

	ioep ioEndpoint

	connectOnce sync.Once
	connectErr  error
	connectorWG sync.WaitGroup

	reserve uint64
}

// Close implements stateio.AsyncReader.Close and stateio.AsyncWriter.Close.
func (rw *asyncReadWriter) Close() error {
	err := rw.closeWithoutEndpoint()
	rw.ioep.Shutdown()
	rw.connectorWG.Wait()
	rw.client.filesMu.Lock()
	rw.ioep.Destroy()
	rw.destroyed = true
	delete(rw.client.files, rw)
	rw.client.filesMu.Unlock()
	rw.client.DecRef()
	return err
}

func (rw *asyncReadWriter) closeWithoutEndpoint() error {
	req := CloseRequest{Handle: rw.handle}
	var resp CloseResponse
	return rw.client.uc.Call("AsyncFileServer.Close", &req, &resp)
}

func (rw *asyncReadWriter) ensureConnected() error {
	rw.connectOnce.Do(func() {
		rw.connectErr = rw.ioep.Connect()
		if rw.isReader {
			rw.ioep.resetForReadSubmissions()
		} else {
			rw.ioep.resetForWriteSubmissions()
		}
	})
	return rw.connectErr
}

// MaxReadBytes implements stateio.AsyncReader.MaxReadBytes.
func (rw *asyncReadWriter) MaxReadBytes() uint64 {
	return uint64(rw.maxIOBytes)
}

// MaxWriteBytes implements stateio.AsyncWriter.MaxWriteBytes.
func (rw *asyncReadWriter) MaxWriteBytes() uint64 {
	return uint64(rw.maxIOBytes)
}

// MaxRanges implements stateio.AsyncReader.MaxRanges and
// stateio.AsyncWriter.MaxRanges.
func (rw *asyncReadWriter) MaxRanges() int {
	return int(rw.maxRanges)
}

// MaxParallel implements stateio.AsyncReader.MaxParallel and
// stateio.AsyncWriter.MaxParallel.
func (rw *asyncReadWriter) MaxParallel() int {
	return int(rw.maxParallel)
}

// NeedRegisterDestinationFD implements
// stateio.AsyncReader.NeedRegisterDestinationFD.
func (rw *asyncReadWriter) NeedRegisterDestinationFD() bool {
	return true
}

// NeedRegisterSourceFD implements
// stateio.AsyncWriter.NeedRegisterSourceFD.
func (rw *asyncReadWriter) NeedRegisterSourceFD() bool {
	return true
}

// RegisterDestinationFD implements stateio.AsyncReader.RegisterDestinationFD.
func (rw *asyncReadWriter) RegisterDestinationFD(fd int32, size uint64, settings []stateio.ClientFileRangeSetting) (stateio.DestinationFile, error) {
	return rw.registerClientFD(fd, size, settings)
}

// RegisterSourceFD implements stateio.AsyncWriter.RegisterSourceFD.
func (rw *asyncReadWriter) RegisterSourceFD(fd int32, size uint64, settings []stateio.ClientFileRangeSetting) (stateio.SourceFile, error) {
	return rw.registerClientFD(fd, size, settings)
}

func (rw *asyncReadWriter) registerClientFD(fd int32, size uint64, settings []stateio.ClientFileRangeSetting) (clientFileHandle, error) {
	dupFD, err := unix.Dup(int(fd))
	if err != nil {
		return 0, fmt.Errorf("failed to dup registered FD: %w", err)
	}
	req := RegisterClientFileRequest{
		Handle: rw.handle,
		FilePayload: urpc.FilePayload{
			Files: []*os.File{os.NewFile(uintptr(dupFD), "stateipc_client_fd")},
		},
		Size:     size,
		Writable: rw.isReader,
		Settings: settings,
	}
	defer req.FilePayload.Files[0].Close()
	var resp RegisterClientFileResponse
	if err := rw.client.uc.Call("AsyncFileServer.RegisterClientFile", &req, &resp); err != nil {
		return 0, err
	}
	return clientFileHandle(resp.Handle), nil
}

// AddRead implements stateio.AsyncReader.AddRead.
func (rw *asyncReadWriter) AddRead(id int, off int64, dstFile stateio.DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	if rw.ensureConnected() != nil {
		return
	}
	subHdr := rw.ioep.scanReadSubmissionHeader()
	*subHdr = readSubmissionHeader{
		ID:        uint32(id),
		Offset:    off,
		DstHandle: uint32(dstFile.(clientFileHandle)),
		NumRanges: 1,
	}
	rw.ioep.scanFileRanges(1)[0] = dstFR
	rw.numSubmissions++
}

// AddReadv implements stateio.AsyncReader.AddReadv.
func (rw *asyncReadWriter) AddReadv(id int, off int64, total uint64, dstFile stateio.DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	if rw.ensureConnected() != nil {
		return
	}
	subHdr := rw.ioep.scanReadSubmissionHeader()
	numRanges := uint32(len(dstFRs))
	*subHdr = readSubmissionHeader{
		ID:        uint32(id),
		Offset:    off,
		DstHandle: uint32(dstFile.(clientFileHandle)),
		NumRanges: numRanges,
	}
	copy(rw.ioep.scanFileRanges(numRanges), dstFRs)
	rw.numSubmissions++
}

// AddWrite implements stateio.AsyncWriter.AddWrite.
func (rw *asyncReadWriter) AddWrite(id int, srcFile stateio.SourceFile, srcFR memmap.FileRange, srcMap []byte) {
	if rw.ensureConnected() != nil {
		return
	}
	subHdr := rw.ioep.scanWriteSubmissionHeader()
	*subHdr = writeSubmissionHeader{
		ID:        uint32(id),
		SrcHandle: uint32(srcFile.(clientFileHandle)),
		NumRanges: 1,
	}
	rw.ioep.scanFileRanges(1)[0] = srcFR
	rw.numSubmissions++
}

// AddWritev implements stateio.AsyncWriter.AddWritev.
func (rw *asyncReadWriter) AddWritev(id int, total uint64, srcFile stateio.SourceFile, srcFRs []memmap.FileRange, srcMaps []unix.Iovec) {
	if rw.ensureConnected() != nil {
		return
	}
	subHdr := rw.ioep.scanWriteSubmissionHeader()
	numRanges := uint32(len(srcFRs))
	*subHdr = writeSubmissionHeader{
		ID:        uint32(id),
		SrcHandle: uint32(srcFile.(clientFileHandle)),
		NumRanges: numRanges,
	}
	copy(rw.ioep.scanFileRanges(numRanges), srcFRs)
	rw.numSubmissions++
}

// Wait implements stateio.AsyncReader.Wait and stateio.AsyncWriter.Wait.
func (rw *asyncReadWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	if err := rw.ensureConnected(); err != nil {
		return cs, err
	}
	minCompletions32 := uint32(max(minCompletions, 0))
	if rw.isReader {
		*rw.ioep.readRequestHeader() = readRequestHeader{MinCompletions: minCompletions32}
	} else {
		*rw.ioep.writeRequestHeader() = writeRequestHeader{
			MinCompletions: minCompletions32,
			Reserve:        rw.reserve,
		}
		rw.reserve = 0
	}
	numCompletions, err := rw.ioep.SendRecv(rw.numSubmissions)
	if err != nil {
		return cs, err
	}
	rw.ioep.resetForCompletions()
	respErrno := rw.ioep.ioResponseHeader().Errno
	for i := uint32(0); i < numCompletions; i++ {
		cmp := rw.ioep.scanCompletion()
		cs = append(cs, stateio.Completion{
			ID:  int(cmp.ID),
			N:   uint64(cmp.N),
			Err: ioErrorFromErrno(cmp.Errno, "completion"),
		})
	}
	rw.numSubmissions = 0
	if rw.isReader {
		rw.ioep.resetForReadSubmissions()
	} else {
		rw.ioep.resetForWriteSubmissions()
	}
	if respErrno != 0 {
		return cs, ioErrorFromErrno(respErrno, "I/O response")
	}
	if numCompletions < minCompletions32 {
		return cs, fmt.Errorf("server returned %d completions (want %d)", numCompletions, minCompletions32)
	}
	return cs, nil
}

// Reserve implements stateio.AsyncWriter.Reserve.
func (rw *asyncReadWriter) Reserve(size uint64) {
	rw.reserve = size
}

// Finalize implements stateio.AsyncWriter.Finalize.
func (rw *asyncReadWriter) Finalize() error {
	if err := rw.ensureConnected(); err != nil {
		return err
	}
	*rw.ioep.writeRequestHeader() = writeRequestHeader{
		Finalize: 1,
	}
	_, err := rw.ioep.SendRecv(0)
	if err != nil {
		return err
	}
	return ioErrorFromErrno(rw.ioep.ioResponseHeader().Errno, "finalize response")
}

// clientFileHandle implements stateio.DestinationFile and
// stateio.SourceFile for asyncReadWriter.
type clientFileHandle uint32
