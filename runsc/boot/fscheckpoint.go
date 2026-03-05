// Copyright 2026 The gVisor Authors.
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

package boot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/version"
)

func convertToKernelFSSaveOpts(args *FSSaveArgs) (kernel.FSSaveOpts, error) {
	opts := kernel.FSSaveOpts{
		RunscVersion:    version.Version(),
		ExitAfterSaving: args.ExitAfterSaving,
	}
	if err := setKernelFSSaveOptsFilesImpl(args, &opts); err != nil {
		return kernel.FSSaveOpts{}, err
	}
	return opts, nil
}

func setKernelFSSaveOptsFilesForLocalCheckpoint(args *FSSaveArgs, opts *kernel.FSSaveOpts) error {
	if len(args.FilePayload.Files) != 4 {
		return fmt.Errorf("got %d files, want 4", len(args.FilePayload.Files))
	}
	manifestFile, err := args.ReleaseFD(0)
	if err != nil {
		return err
	}
	multiTarFile, err := args.ReleaseFD(1)
	if err != nil {
		return err
	}
	pagesMetadataFile, err := args.ReleaseFD(2)
	if err != nil {
		return err
	}
	pagesFile, err := args.ReleaseFD(3)
	if err != nil {
		return err
	}
	opts.ManifestFile = stateio.NewBufioWriteCloser(manifestFile)
	opts.MultiTarFile = stateio.NewBufioWriteCloser(multiTarFile)
	opts.PagesMetadataFile = stateio.NewBufioWriteCloser(pagesMetadataFile)
	opts.PagesFile = stateio.NewPagesFileFDWriterDefault(int32(pagesFile.Release()))
	return nil
}

// fsRestore holds the state of a filesystem checkpoint restore.
type fsRestore struct {
	wg sync.WaitGroup

	// immutable
	getPagesMetadata func() ([]byte, error)
	getMultiTar      func() ([]byte, error)

	// immutable after wg.Wait()
	manifestErr error
	apfl        *pgalloc.AsyncPagesFileLoad
	mfs         map[checkpoint.ResourceID]*fscheckpoint.MemoryFile
	tmpfs       map[checkpoint.ResourceID]*fscheckpoint.Tmpfs
}

// fsRestoreOpts holds options to startFSRestore.
type fsRestoreOpts struct {
	// These correspond to files specified by the fscheckpoint package, and are
	// all required.
	ManifestFile      io.ReadCloser
	MultiTarFile      io.ReadCloser
	PagesMetadataFile io.ReadCloser
	PagesFile         stateio.AsyncReader
}

func makeFSRestoreOptsForLocalCheckpoint(args *Args) (fsRestoreOpts, error) {
	if len(args.FSRestoreFDs) != 4 {
		return fsRestoreOpts{}, fmt.Errorf("got %d files in -fs-restore-fds, want 4", len(args.FSRestoreFDs))
	}
	return fsRestoreOpts{
		ManifestFile:      stateio.NewBufioReadCloser(args.FSRestoreFDs[0].ReleaseToFile(checkpointfiles.FSCheckpointManifestFileName)),
		MultiTarFile:      stateio.NewBufioReadCloser(args.FSRestoreFDs[1].ReleaseToFile(checkpointfiles.FSCheckpointMultiTarFileName)),
		PagesMetadataFile: stateio.NewBufioReadCloser(args.FSRestoreFDs[2].ReleaseToFile(checkpointfiles.PagesMetadataFileName)),
		PagesFile:         stateio.NewPagesFileFDReaderDefault(int32(args.FSRestoreFDs[3].Release())),
	}, nil
}

// startFSRestore takes ownership of resources in opts.
func startFSRestore(opts *fsRestoreOpts) (*fsRestore, error) {
	fsr := &fsRestore{
		mfs:   make(map[checkpoint.ResourceID]*fscheckpoint.MemoryFile),
		tmpfs: make(map[checkpoint.ResourceID]*fscheckpoint.Tmpfs),
	}

	// TODO: Currently we read the whole pages metadata file into a []byte,
	// then pass pieces of that []byte to MemoryFile construction. This is
	// necessary because opts.PagesMetadataFile is io.Reader (read
	// sequentially), and tmpfs filesystems and their private MemoryFiles may
	// be restored in a different order than checkpoint order (disk-backed
	// filestore files are not available until container creation).
	//
	// We could make opts.PagesMetadataFile io.ReaderAt to avoid this copy.
	// However, when the multi-tar file is accessed via stateio.AsyncReader,
	// this requires an implementation of io.ReaderAt that wraps
	// stateio.AsyncReader, akin to stateio.BufReader. AsyncReader already
	// supports random reads, but has a fixed maximum parallelism per
	// AsyncReader that would need to be shared between readers. Furthermore,
	// BufReader asynchronously fills its buffer with reads to minimize
	// latency; our io.ReaderAt implementation would need to do something
	// comparable to avoid regressions.
	//
	// Alternatively, we could implement io.ReaderAt by asynchronously
	// buffering the whole file in memory, which is probably better overall
	// (equivalent to what we are doing now, but permits reading parts of the
	// file that have been read before the whole file is read) but requires
	// adding a stateio.AsyncReader method to get file size.
	//
	// All of the above also applies to the multi-tar file.
	readOnce := func(desc string, optsR *io.ReadCloser) func() ([]byte, error) {
		r := *optsR
		*optsR = nil
		f := sync.OnceValues(func() ([]byte, error) {
			timeStart := time.Now()
			data, err := io.ReadAll(r)
			dur := time.Since(timeStart)
			// Close r immediately to release any memory used for buffering.
			r.Close()
			r = nil
			if err == nil {
				log.Infof("Read filesystem checkpoint %s (%d bytes) in %s", desc, len(data), dur)
			}
			return data, err
		})
		// Start reading immediately.
		go f()
		return f
	}
	fsr.getPagesMetadata = readOnce("pages metadata file", &opts.PagesMetadataFile)
	fsr.getMultiTar = readOnce("multi-tar file", &opts.MultiTarFile)

	// Read and handle the manifest in parallel.
	fsr.manifestErr = fmt.Errorf("loading manifest panicked")
	fsr.wg.Go(func() {
		defer func() {
			if opts.ManifestFile != nil {
				opts.ManifestFile.Close()
				opts.ManifestFile = nil
			}
			if opts.PagesFile != nil {
				opts.PagesFile.Close()
				opts.PagesFile = nil
			}
		}()
		fsr.manifestErr = func() error {
			var manifest fscheckpoint.Manifest
			timeStart := time.Now()
			if err := json.NewDecoder(opts.ManifestFile).Decode(&manifest); err != nil {
				return fmt.Errorf("failed to read manifest: %w", err)
			}
			log.Infof("Read filesystem checkpoint manifest in %s", time.Since(timeStart))
			if manifest.Version != 0 {
				return fmt.Errorf("unsupported filesystem checkpoint version: %d", manifest.Version)
			}
			if manifest.RunscVersion != version.Version() {
				return fmt.Errorf("filesystem checkpoint runsc version %q does not match current runsc version %q", manifest.RunscVersion, version.Version())
			}
			if manifest.PageSize != hostarch.PageSize {
				return fmt.Errorf("filesystem checkpoint page size %d does not match current page size %d", manifest.PageSize, hostarch.PageSize)
			}
			if endian := hostarch.EndianString(); manifest.Endian != endian {
				return fmt.Errorf("filesystem checkpoint endianness %q does not match current endianness %q", manifest.Endian, endian)
			}

			apfl, err := pgalloc.StartAsyncPagesFileLoad(opts.PagesFile /* transfers ownership */, func(err error) {
				if err != nil {
					log.Warningf("Failed to load filesystem checkpoint pages: %v", err)
				} else if log.IsLogging(log.Debug) {
					log.Debugf("Finished loading filesystem checkpoint pages")
				}
			}, nil)
			opts.PagesFile = nil
			if err != nil {
				return fmt.Errorf("failed to start async page loading: %w", err)
			}
			fsr.apfl = apfl
			for i := range manifest.MemoryFiles {
				mmf := &manifest.MemoryFiles[i]
				fsr.mfs[mmf.ResourceID] = mmf
			}
			for i := range manifest.Tmpfs {
				mt := &manifest.Tmpfs[i]
				fsr.tmpfs[mt.ResourceID] = mt
			}
			// Note that apfl.MemoryFilesDone() will never be called. This is
			// because if a container fails and is restarted, we also want to
			// restore the filesystem of the restarted container, so we need to
			// keep filesystem restore operational indefinitely.
			return nil
		}()
	})

	return fsr, nil
}

func (fsr *fsRestore) manifestMemoryFile(id checkpoint.ResourceID) (*fscheckpoint.MemoryFile, error) {
	if fsr == nil {
		return nil, nil
	}
	fsr.wg.Wait()
	if fsr.manifestErr != nil {
		return nil, fsr.manifestErr
	}
	return fsr.mfs[id], nil
}

func (fsr *fsRestore) memoryFileLoadArgs(id checkpoint.ResourceID) (io.Reader, uint64, error) {
	mmf, err := fsr.manifestMemoryFile(id)
	if err != nil {
		return nil, 0, err
	}
	if mmf == nil {
		return nil, 0, nil
	}
	pagesMetadata, err := fsr.getPagesMetadata()
	if mmf.PagesMetadataEnd <= uint64(len(pagesMetadata)) {
		return bytes.NewReader(pagesMetadata[mmf.PagesMetadataStart:mmf.PagesMetadataEnd]), mmf.PagesStart, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read pages metadata: %w", err)
	}
	return nil, 0, fmt.Errorf("MemoryFile %q has pages metadata range [%d, %d) beyond pages metadata file size %d", mmf.ResourceID, mmf.PagesMetadataStart, mmf.PagesMetadataEnd, len(pagesMetadata))
}

func (fsr *fsRestore) manifestTmpfs(id checkpoint.ResourceID) (*fscheckpoint.Tmpfs, error) {
	if fsr == nil {
		return nil, nil
	}
	fsr.wg.Wait()
	if fsr.manifestErr != nil {
		return nil, fsr.manifestErr
	}
	return fsr.tmpfs[id], nil
}

func (fsr *fsRestore) tmpfsSourceTar(id checkpoint.ResourceID) (io.ReadCloser, error) {
	mt, err := fsr.manifestTmpfs(id)
	if err != nil {
		return nil, err
	}
	if mt == nil {
		return nil, nil
	}
	multiTar, err := fsr.getMultiTar()
	if mt.TarEnd <= uint64(len(multiTar)) {
		return io.NopCloser(bytes.NewReader(multiTar[mt.TarStart:mt.TarEnd])), nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read tar archive: %w", err)
	}
	return nil, fmt.Errorf("tmpfs %q has tar range [%d, %d) beyond multi-tar file size %d", mt.ResourceID, mt.TarStart, mt.TarEnd, len(multiTar))
}
