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
	"math"
	"math/bits"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

// AsyncFileServer is a URPC handler that serves files to a stateipc client.
type AsyncFileServer struct {
	// asyncFileServer is the underlying implementation. Some methods are
	// defined on asyncFileServer rather than AsyncFileServer, since
	// urpc.Server.Register disallows non-RPC methods (including unexported
	// methods) on handlers.
	asyncFileServer
}

type asyncFileServer struct {
	filesMu        sync.Mutex
	files          map[uint32]*openFile
	nextFileHandle uint32

	pwa flipcall.PacketWindowAllocator

	impl AsyncFileServerImpl
}

// AsyncFileServerImpl contains implementation details for an AsyncFileServer.
type AsyncFileServerImpl interface {
	// Destroy is called when the AsyncFileServer stops.
	Destroy()

	// OpenRead opens a file for reading.
	OpenRead(path string) (stateio.AsyncReader, error)

	// OpenWrite opens a file for writing.
	OpenWrite(path string) (stateio.AsyncWriter, error)
}

// NewAsyncFileServer returns a new AsyncFileServer.
func NewAsyncFileServer(impl AsyncFileServerImpl) (*AsyncFileServer, error) {
	s := &AsyncFileServer{
		asyncFileServer: asyncFileServer{
			files: make(map[uint32]*openFile),
			impl:  impl,
		},
	}
	if err := s.pwa.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize flipcall packet window allocator: %w", err)
	}
	return s, nil
}

// Stop implements urpc.Stopper.Stop.
func (s *AsyncFileServer) Stop() {
	s.pwa.Destroy()

	// Close all files.
	s.filesMu.Lock()
	files := s.files
	for _, f := range files {
		if !f.destroyed {
			f.ioep.Shutdown()
		}
	}
	s.filesMu.Unlock()
	for _, f := range files {
		f.wg.Wait()
	}

	s.impl.Destroy()
}

// Open opens a file.
func (s *AsyncFileServer) Open(req *OpenRequest, resp *OpenResponse) error {
	var cu cleanup.Cleanup
	defer cu.Clean()

	var f *openFile
	switch req.Mode {
	case OpenModeRead:
		ar, err := s.impl.OpenRead(req.Path)
		if err != nil {
			return err
		}
		cu.Add(func() { ar.Close() })
		maxParallel := min(ar.MaxParallel(), maxMaxParallel)
		rf := &readFile{
			openFile: openFile{
				server:      s,
				path:        req.Path,
				maxIOBytes:  uint32(min(ar.MaxReadBytes(), math.MaxUint32)),
				maxRanges:   uint32(min(ar.MaxRanges(), maxMaxRanges)),
				maxParallel: uint32(maxParallel),
				slicesUsed:  make([]asyncIOSlices, maxParallel),
			},
			ar: ar,
		}
		rf.impl = rf
		f = &rf.openFile
	case OpenModeWrite:
		aw, err := s.impl.OpenWrite(req.Path)
		if err != nil {
			return err
		}
		cu.Add(func() { aw.Close() })
		maxParallel := min(aw.MaxParallel(), maxMaxParallel)
		wf := &writeFile{
			openFile: openFile{
				server:      s,
				path:        req.Path,
				maxIOBytes:  uint32(min(aw.MaxWriteBytes(), math.MaxUint32)),
				maxRanges:   uint32(min(aw.MaxRanges(), maxMaxRanges)),
				maxParallel: uint32(maxParallel),
				slicesUsed:  make([]asyncIOSlices, maxParallel),
			},
			aw: aw,
		}
		wf.impl = wf
		f = &wf.openFile
	default:
		return fmt.Errorf("unknown open mode %v", req.Mode)
	}
	f.ids.init(f.maxParallel)
	resp.MaxIOBytes = f.maxIOBytes
	resp.MaxRanges = f.maxRanges
	resp.MaxParallel = f.maxParallel

	// Initialize the Flipcall connection.
	pwd, err := s.pwa.Allocate(flipcall.PacketWindowLengthForDataCap(getDataSize(f.maxRanges, f.maxParallel, req.Mode)))
	if err != nil {
		return fmt.Errorf("failed to allocate flipcall packet window: %w", err)
	}
	resp.PacketWindowOffset = pwd.Offset
	resp.PacketWindowLength = pwd.Length
	dupFD, err := unix.Dup(pwd.FD)
	if err != nil {
		return fmt.Errorf("failed to dup flipcall packet window FD: %w", err)
	}
	resp.FilePayload.Files = append(resp.FilePayload.Files, os.NewFile(uintptr(dupFD), "flipcall_packet_window_stateipc_openfile"))
	cu.Add(func() { resp.FilePayload.Files[0].Close() })
	if err := f.ioep.Init(flipcall.ServerSide, pwd); err != nil {
		return fmt.Errorf("failed to initialize server flipcall endpoint: %w", err)
	}
	cu.Add(f.ioep.Destroy)

	// Register a server file handle.
	s.filesMu.Lock()
	handle := s.nextFileHandle
	s.nextFileHandle++
	if _, ok := s.files[handle]; ok {
		// This should only be possible due to wraparound, which shouldn't
		// happen under normal operation.
		log.Warningf("stateipc.AsyncFileServer(%s): server file handle reuse at handle %d", f.path, handle)
		return fmt.Errorf("all server file handles in use")
	}
	s.files[handle] = f
	resp.Handle = handle
	f.wg.Add(1)
	s.filesMu.Unlock()

	f.impl.startServing(handle)
	cu.Release()
	return nil
}

// Close closes a open file.
func (s *AsyncFileServer) Close(req *CloseRequest, resp *CloseResponse) error {
	s.filesMu.Lock()
	f := s.files[req.Handle]
	if f == nil {
		s.filesMu.Unlock()
		return fmt.Errorf("invalid file handle: %v", req.Handle)
	}
	delete(s.files, req.Handle)
	if !f.destroyed {
		f.ioep.Shutdown()
	}
	s.filesMu.Unlock()
	f.wg.Wait()
	return f.closeErr
}

// RegisterClientFile registers a client-provided memory-mappable file as a
// destination for reads from, or source for writes to, the server file with
// the given handle.
func (s *AsyncFileServer) RegisterClientFile(req *RegisterClientFileRequest, resp *RegisterClientFileResponse) error {
	if got := len(req.FilePayload.Files); got != 1 {
		for _, file := range req.FilePayload.Files {
			file.Close()
		}
		return fmt.Errorf("got %d file descriptors, expected 1", got)
	}
	// The file isn't needed after mapping and registration.
	fd := req.FilePayload.Files[0].Fd()
	defer req.FilePayload.Files[0].Close()

	// Set up the mapping of the client file.
	var (
		mapping []byte
		cu      cleanup.Cleanup
	)
	defer cu.Clean()
	if req.Size > 0 {
		prot := unix.PROT_READ
		if req.Writable {
			prot |= unix.PROT_WRITE
		}
		var err error
		mapping, err = unix.Mmap(int(fd), 0 /* offset */, int(req.Size), prot, unix.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("failed to map file: %w", err)
		}
		cu.Add(func() { unix.Munmap(mapping) })
		for _, setting := range req.Settings {
			if !isValidFileRange(setting.FileRange, len(mapping)) {
				return fmt.Errorf("invalid FileRange: %v", setting.FileRange)
			}
			switch setting.Property {
			case stateio.PropertyHugepage:
				if err := unix.Madvise(mapping[setting.FileRange.Start:setting.FileRange.End], unix.MADV_HUGEPAGE); err != nil {
					// Log this failure but continue.
					log.Warningf("stateipc.FileServer(%p): madvise(MADV_HUGEPAGE) failed: %v", s, err)
				}
			case stateio.PropertyNoHugepage:
				if err := unix.Madvise(mapping[setting.FileRange.Start:setting.FileRange.End], unix.MADV_NOHUGEPAGE); err != nil {
					// Log this failure but continue.
					log.Warningf("stateipc.FileServer(%p): madvise(MADV_NOHUGEPAGE) failed: %v", s, err)
				}
			default:
				return fmt.Errorf("invalid property: %v", setting.Property)
			}
		}
	} else {
		if len(req.Settings) != 0 {
			return fmt.Errorf("invalid FileRange given size=0: %v", req.Settings[0].FileRange)
		}
	}

	s.filesMu.Lock()
	defer s.filesMu.Unlock()
	f := s.files[req.Handle]
	if f == nil {
		return fmt.Errorf("invalid server file handle: %v", req.Handle)
	}
	handle, err := f.impl.registerClientFD(req, int32(fd), mapping)
	if err != nil {
		return err
	}
	resp.Handle = handle
	cu.Release()
	return nil
}

// openFile represents an opened server file.
type openFile struct {
	// Immutable fields:
	server      *AsyncFileServer
	path        string
	maxIOBytes  uint32
	maxRanges   uint32
	maxParallel uint32

	// destroyed is true if ioep.Destroy() has been called. destroyed is
	// protected by server.filesMu.
	destroyed bool

	// wg is 1 if the reader goroutine is running.
	wg sync.WaitGroup

	// closeErr is the error returned by ar.Close().
	closeErr error

	ioep ioEndpoint

	// ids tracks in-use IDs. ids is exclusive to the reader or writer
	// goroutine.
	ids idsSet

	// slicesUsed maps in-use IDs to the slices that they are using. slicesUsed
	// is exclusive to the reader or writer goroutine.
	slicesUsed []asyncIOSlices

	// slicesUnused is a stack of unused (reusable) slices. slicesUnused is
	// exclusive to the reader or writer goroutine.
	slicesUnused []asyncIOSlices

	// impl is the containing readFile or writeFile. impl is immutable.
	impl openFileImpl
}

type openFileImpl interface {
	startServing(handle uint32)
	registerClientFD(req *RegisterClientFileRequest, fd int32, mapping []byte) (uint32, error)
}

// readFile represents a server file opened for reading.
type readFile struct {
	openFile
	ar                stateio.AsyncReader
	dstFiles          destinationFileAtomicPtrMap
	nextDstFileHandle uint32
}

func (f *readFile) startServing(handle uint32) {
	if log.IsLogging(log.Debug) {
		log.Debugf("stateipc.readFile(%s): opened with handle %d", f.path, handle)
	}
	go f.readerMain()
}

func (f *readFile) readerMain() {
	defer func() {
		f.closeErr = f.ar.Close()
		f.server.filesMu.Lock()
		f.ioep.Destroy()
		f.destroyed = true
		f.server.filesMu.Unlock()
		f.wg.Done() // allow AsyncFileServer.Close() to return
		for _, dstFile := range f.dstFiles.Range {
			dstFile.destroy()
		}
	}()

	var (
		numSubmissions uint32
		numCompletions uint32
		recvErr        error
		cs             []stateio.Completion
	)
	for numSubmissions, recvErr = f.ioep.RecvFirst(); recvErr == nil; numSubmissions, recvErr = f.ioep.SendRecv(numCompletions) {
		if numSubmissions > f.maxParallel {
			log.Warningf("stateipc.readFile(%s): got %d submissions (max %d)", f.path, numSubmissions, f.maxParallel)
			f.ioep.Shutdown()
			return
		}
		f.ioep.resetForReadSubmissions()
		for range numSubmissions {
			cs = f.handleReadSubmission(cs)
		}
		minCompletions := max(int(f.ioep.readRequestHeader().MinCompletions)-len(cs), 0)
		var err error
		cs, err = f.ar.Wait(cs, minCompletions)
		numCompletions = uint32(len(cs))
		f.ioep.resetForCompletions()
		*f.ioep.ioResponseHeader() = ioResponseHeader{
			Errno: ioErrnoFromError(err, "wait"),
		}
		for _, c := range cs {
			*f.ioep.scanCompletion() = ioCompletion{
				ID:    uint32(c.ID),
				N:     uint32(c.N),
				Errno: ioErrnoFromError(c.Err, "read"),
			}
			f.ids.clear(uint32(c.ID))
			f.putSlices(f.slicesUsed[c.ID])
		}
		cs = cs[:0]
		if err != nil {
			log.Warningf("stateipc.readFile(%s): AsyncReader.Wait error: %v", f.path, err)
			f.ioep.SendLast(numCompletions)
			return
		}
	}
	// AsyncFileServer.Close shuts down f.ioep, so don't log this.
	if _, ok := recvErr.(flipcall.ShutdownError); !ok {
		log.Warningf("stateipc.readFile(%s): receive error: %v", f.path, recvErr)
	}
}

func (f *readFile) handleReadSubmission(cs []stateio.Completion) []stateio.Completion {
	subHdr := f.ioep.scanReadSubmissionHeader()
	id := subHdr.ID
	if id >= f.maxParallel {
		log.Warningf("stateipc.readFile(%s): invalid ID %d", f.path, id)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	if f.ids.isSet(id) {
		log.Warningf("stateipc.readFile(%s): reuse of inflight ID %d", f.path, id)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	dfh := subHdr.DstHandle
	df := f.dstFiles.Load(dfh)
	if df == nil {
		log.Warningf("stateipc.readFile(%s): invalid destination file handle %d", f.path, dfh)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	numRanges := subHdr.NumRanges
	if numRanges == 0 || numRanges > f.maxRanges {
		log.Warningf("stateipc.readFile(%s): invalid NumRanges %d (max %d)", f.path, numRanges, f.maxRanges)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}

	if numRanges == 1 {
		fr := f.ioep.scanFileRanges(1)[0]
		if !isValidFileRange(fr, len(df.mapping)) {
			log.Warningf("stateipc.readFile(%s): invalid destination file range %v for destination handle %d, file size %d", f.path, fr, dfh, len(df.mapping))
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		if fr.Length() > uint64(f.maxIOBytes) {
			log.Warningf("stateipc.readFile(%s): oversize read (%d bytes) after destination file range %v", f.path, fr.Length(), fr)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		f.ar.AddRead(int(id), subHdr.Offset, df.df, fr, df.mapping[fr.Start:fr.End])
		f.ids.set(id)
		f.slicesUsed[id] = asyncIOSlices{}
		return cs
	}

	slices := f.getSlices(numRanges)
	copy(slices.frs, f.ioep.scanFileRanges(numRanges))
	total := uint64(0)
	for i, fr := range slices.frs {
		if !isValidFileRange(fr, len(df.mapping)) {
			log.Warningf("stateipc.readFile(%s): invalid destination file range %v for destination file size %d", f.path, fr, len(df.mapping))
			f.putSlices(slices)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		newTotal := total + fr.Length()
		if newTotal > uint64(f.maxIOBytes) || newTotal < total {
			log.Warningf("stateipc.readFile(%s): oversize read (%d bytes or overflow) after destination file range %v", f.path, newTotal, fr)
			f.putSlices(slices)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		total = newTotal
		slices.iovecs[i] = unix.Iovec{
			Base: &df.mapping[fr.Start],
			Len:  fr.Length(),
		}
	}
	f.ar.AddReadv(int(id), subHdr.Offset, total, df.df, slices.frs, slices.iovecs)
	f.ids.set(id)
	f.slicesUsed[id] = slices
	return cs
}

func (f *readFile) registerClientFD(req *RegisterClientFileRequest, fd int32, mapping []byte) (uint32, error) {
	if !req.Writable {
		return 0, fmt.Errorf("client file must be writable for readable server file")
	}
	df, err := f.ar.RegisterDestinationFD(fd, req.Size, req.Settings)
	if err != nil {
		return 0, fmt.Errorf("failed to register destination FD: %w", err)
	}
	handle := f.nextDstFileHandle
	f.nextDstFileHandle++
	if f.dstFiles.CompareAndSwap(handle, nil, &destinationFile{
		df:      df,
		mapping: mapping,
	}) != nil {
		// This should only be possible due to wraparound, which shouldn't
		// happen under normal operation.
		log.Warningf("stateipc.readFile(%s): destination file handle reuse at handle %d", f.path, handle)
		return 0, fmt.Errorf("all destination file handles in use")
	}
	if log.IsLogging(log.Debug) {
		log.Debugf("stateipc.readFile(%s): registered destination file handle %d, size %d", f.path, handle, req.Size)
	}
	return handle, nil
}

// destinationFile represents a registered destination file on the server.
type destinationFile struct {
	df      stateio.DestinationFile
	mapping []byte
}

func (df *destinationFile) destroy() {
	if df.mapping != nil {
		unix.Munmap(df.mapping)
	}
}

// writeFile represents a server file opened for writing.
type writeFile struct {
	openFile
	aw                stateio.AsyncWriter
	srcFiles          sourceFileAtomicPtrMap
	nextSrcFileHandle uint32
	numInflight       int
	maxReserve        uint64
}

func (f *writeFile) startServing(handle uint32) {
	if log.IsLogging(log.Debug) {
		log.Debugf("stateipc.writeFile(%s): opened with handle %d", f.path, handle)
	}
	go f.writerMain()
}

func (f *writeFile) writerMain() {
	defer func() {
		f.closeErr = f.aw.Close()
		f.server.filesMu.Lock()
		f.ioep.Destroy()
		f.destroyed = true
		f.server.filesMu.Unlock()
		f.wg.Done() // allow AsyncFileServer.Close() to return
		for _, srcFile := range f.srcFiles.Range {
			srcFile.destroy()
		}
	}()

	var (
		numSubmissions uint32
		numCompletions uint32
		recvErr        error
		cs             []stateio.Completion
	)

	for numSubmissions, recvErr = f.ioep.RecvFirst(); recvErr == nil; numSubmissions, recvErr = f.ioep.SendRecv(numCompletions) {
		reqHdr := f.ioep.writeRequestHeader()
		if reqHdr.Finalize != 0 {
			var err error
			switch {
			case numSubmissions != 0:
				log.Warningf("stateipc.writeFile(%s): Finalize called with %d write submissions", f.path, numSubmissions)
				err = unix.EINVAL
			case f.numInflight != 0:
				log.Warningf("stateipc.writeFile(%s): Finalize called with %d writes inflight", f.path, f.numInflight)
				err = unix.EINVAL
			default:
				err = f.aw.Finalize()
			}
			*f.ioep.ioResponseHeader() = ioResponseHeader{
				Errno: ioErrnoFromError(err, "finalize"),
			}
			f.ioep.SendLast(0)
			return
		}
		if reserve := reqHdr.Reserve; reserve != 0 {
			if reserve < f.maxReserve {
				log.Warningf("stateipc.writeFile(%s): ignoring reservation decrease from %d to %d", f.path, f.maxReserve, reserve)
			} else {
				f.aw.Reserve(reserve)
				f.maxReserve = reserve
			}
		}
		if numSubmissions > f.maxParallel {
			log.Warningf("stateipc.writeFile(%s): got %d submissions (max %d)", f.path, numSubmissions, f.maxParallel)
			f.ioep.Shutdown()
			return
		}
		f.ioep.resetForWriteSubmissions()
		for range numSubmissions {
			cs = f.handleWriteSubmission(cs)
		}
		minCompletions := max(int(reqHdr.MinCompletions)-len(cs), 0)
		var err error
		cs, err = f.aw.Wait(cs, minCompletions)
		numCompletions = uint32(len(cs))
		f.ioep.resetForCompletions()
		*f.ioep.ioResponseHeader() = ioResponseHeader{
			Errno: ioErrnoFromError(err, "wait"),
		}
		for _, c := range cs {
			*f.ioep.scanCompletion() = ioCompletion{
				ID:    uint32(c.ID),
				N:     uint32(c.N),
				Errno: ioErrnoFromError(c.Err, "write"),
			}
			f.ids.clear(uint32(c.ID))
			f.putSlices(f.slicesUsed[c.ID])
		}
		f.numInflight -= len(cs)
		cs = cs[:0]
		if err != nil {
			log.Warningf("stateipc.writeFile(%s): AsyncReader.Wait error: %v", f.path, err)
			f.ioep.SendLast(numCompletions)
			return
		}
	}
	// AsyncFileServer.Close shuts down f.ioep, so don't log this.
	if _, ok := recvErr.(flipcall.ShutdownError); !ok {
		log.Warningf("stateipc.writeFile(%s): receive error: %v", f.path, recvErr)
	}
}

func (f *writeFile) handleWriteSubmission(cs []stateio.Completion) []stateio.Completion {
	subHdr := f.ioep.scanWriteSubmissionHeader()
	id := subHdr.ID
	if id >= f.maxParallel {
		log.Warningf("stateipc.writeFile(%s): invalid ID %d", f.path, id)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	if f.ids.isSet(id) {
		log.Warningf("stateipc.writeFile(%s): reuse of inflight ID %d", f.path, id)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	sfh := subHdr.SrcHandle
	sf := f.srcFiles.Load(sfh)
	if sf == nil {
		log.Warningf("stateipc.writeFile(%s): invalid source file handle %d", f.path, sfh)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}
	numRanges := subHdr.NumRanges
	if numRanges == 0 || numRanges > f.maxRanges {
		log.Warningf("stateipc.writeFile(%s): invalid NumRanges %d (max %d)", f.path, numRanges, f.maxRanges)
		return appendErrnoCompletion(cs, id, unix.EINVAL)
	}

	if numRanges == 1 {
		fr := f.ioep.scanFileRanges(1)[0]
		if !isValidFileRange(fr, len(sf.mapping)) {
			log.Warningf("stateipc.writeFile(%s): invalid source file range %v for source handle %d, file size %d", f.path, fr, sfh, len(sf.mapping))
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		if fr.Length() > uint64(f.maxIOBytes) {
			log.Warningf("stateipc.writeFile(%s): oversize write (%d bytes) after source file range %v", f.path, fr.Length(), fr)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		f.aw.AddWrite(int(id), sf.sf, fr, sf.mapping[fr.Start:fr.End])
		f.ids.set(id)
		f.slicesUsed[id] = asyncIOSlices{}
		f.numInflight++
		return cs
	}

	slices := f.getSlices(numRanges)
	copy(slices.frs, f.ioep.scanFileRanges(numRanges))
	total := uint64(0)
	for i, fr := range slices.frs {
		if !isValidFileRange(fr, len(sf.mapping)) {
			log.Warningf("stateipc.writeFile(%s): invalid source file range %v for source file size %d", f.path, fr, len(sf.mapping))
			f.putSlices(slices)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		newTotal := total + fr.Length()
		if newTotal > uint64(f.maxIOBytes) || newTotal < total {
			log.Warningf("stateipc.writeFile(%s): oversize write (%d bytes or overflow) after source file range %v", f.path, newTotal, fr)
			f.putSlices(slices)
			return appendErrnoCompletion(cs, id, unix.EINVAL)
		}
		total = newTotal
		slices.iovecs[i] = unix.Iovec{
			Base: &sf.mapping[fr.Start],
			Len:  fr.Length(),
		}
	}
	f.aw.AddWritev(int(id), total, sf.sf, slices.frs, slices.iovecs)
	f.ids.set(id)
	f.slicesUsed[id] = slices
	f.numInflight++
	return cs
}

func (f *writeFile) registerClientFD(req *RegisterClientFileRequest, fd int32, mapping []byte) (uint32, error) {
	sf, err := f.aw.RegisterSourceFD(fd, req.Size, req.Settings)
	if err != nil {
		return 0, fmt.Errorf("failed to register source FD: %w", err)
	}
	handle := f.nextSrcFileHandle
	f.nextSrcFileHandle++
	if f.srcFiles.CompareAndSwap(handle, nil, &sourceFile{
		sf:      sf,
		mapping: mapping,
	}) != nil {
		// This should only be possible due to wraparound, which shouldn't
		// happen under normal operation.
		log.Warningf("stateipc.writeFile(%s): source file handle reuse at handle %d", f.path, handle)
		return 0, fmt.Errorf("all source file handles in use")
	}
	if log.IsLogging(log.Debug) {
		log.Debugf("stateipc.writeFile(%s): registered source file handle %d, size %d", f.path, handle, req.Size)
	}
	return handle, nil
}

// sourceFile represents a registered source file on the server.
type sourceFile struct {
	sf      stateio.SourceFile
	mapping []byte
}

func (sf *sourceFile) destroy() {
	if sf.mapping != nil {
		unix.Munmap(sf.mapping)
	}
}

// Common to all openFiles:

func isValidFileRange(fr memmap.FileRange, mapLen int) bool {
	return fr.WellFormed() && fr.Length() > 0 && fr.End <= uint64(mapLen)
}

func appendErrnoCompletion(cs []stateio.Completion, id uint32, errno unix.Errno) []stateio.Completion {
	return append(cs, stateio.Completion{
		ID:  int(id),
		Err: errno,
	})
}

// idsSet tracks in-use request IDs.
type idsSet struct {
	bitmap []uint
}

func (s *idsSet) init(maxParallel uint32) {
	s.bitmap = make([]uint, (maxParallel+bits.UintSize-1)/bits.UintSize)
}

func (s *idsSet) set(id uint32) {
	s.bitmap[id/bits.UintSize] |= uint(1) << (id % bits.UintSize)
}

func (s *idsSet) clear(id uint32) {
	s.bitmap[id/bits.UintSize] &^= uint(1) << (id % bits.UintSize)
}

func (s *idsSet) isSet(id uint32) bool {
	return s.bitmap[id/bits.UintSize]&(uint(1)<<(id%bits.UintSize)) != 0
}

func (s *idsSet) count() uint32 {
	total := uint32(0)
	for _, w := range s.bitmap {
		total += uint32(bits.OnesCount(w))
	}
	return total
}

// asyncIOSlices holds slices passed to AsyncReader.AddReadv or
// AsyncWriter.AddWritev.
type asyncIOSlices struct {
	frs    []memmap.FileRange
	iovecs []unix.Iovec
}

func (f *openFile) getSlices(numRanges uint32) asyncIOSlices {
	if len(f.slicesUnused) != 0 {
		slices := f.slicesUnused[len(f.slicesUnused)-1]
		f.slicesUnused = f.slicesUnused[:len(f.slicesUnused)-1]
		slices.frs = slices.frs[:numRanges]
		slices.iovecs = slices.iovecs[:numRanges]
		return slices
	}
	return asyncIOSlices{
		frs:    make([]memmap.FileRange, numRanges, f.maxRanges),
		iovecs: make([]unix.Iovec, numRanges, f.maxRanges),
	}
}

func (f *openFile) putSlices(slices asyncIOSlices) {
	if slices.frs != nil {
		f.slicesUnused = append(f.slicesUnused, slices)
	}
}

// clientFileHandleHasher is the hasher for destinationFileAtomicPtrMap and
// sourceFileAtomicPtrMap.
type clientFileHandleHasher struct{}

func (*clientFileHandleHasher) Init() {}

func (*clientFileHandleHasher) Hash(handle uint32) uintptr {
	// Since client file handles are assigned in order by the server and never
	// released, the identity hash function is reasonable and turns
	// destination/sourceFileAtomicPtrMap into a seqcount-protected array.
	return uintptr(handle)
}
