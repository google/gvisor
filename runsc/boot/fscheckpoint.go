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
	"fmt"
	"io"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	fspb "gvisor.dev/gvisor/pkg/sentry/fscheckpoint/fscheckpoint_proto_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

const (
	annotationFSCheckpointPrefix = "dev.gvisor.internal.fscheckpoint."

	// annotationFSCheckpointEnable indicates whether files under /proc/gvisor
	// should be present in the container to allow the workload to trigger a
	// filesystem checkpoint.
	annotationFSCheckpointEnable = annotationFSCheckpointPrefix + "enable"

	// annotationFSCheckpointPath is the path to the directory where the
	// filesystem checkpoint files will be created. When present, it allows for
	// the workload running inside to trigger a filesystem checkpoint without
	// having to use the runsc CLI.
	annotationFSCheckpointPath = annotationFSCheckpointPrefix + "path"

	// annotationFSCheckpointResume indicates whether the sandbox should
	// continue running after filesystem checkpoint saving triggered via
	// /proc/gvisor. Optional, defaults to false.
	annotationFSCheckpointResume = annotationFSCheckpointPrefix + "resume"

	// annotationFSCheckpointDirect indicates whether filesystem checkpoint
	// I/Os triggered via /proc/gvisor should use O_DIRECT. Optional, defaults
	// to false.
	annotationFSCheckpointDirect = annotationFSCheckpointPrefix + "direct"

	// annotationFSCheckpointPaths is a comma-separated list of paths inside the
	// containers to save. Optional.
	annotationFSCheckpointPaths = annotationFSCheckpointPrefix + "paths"
)

// GetAnnotationFSCheckpointPath returns the filesystem checkpoint path
// specified in the container annotation. Return empty string if no annotation
// is specified.
func GetAnnotationFSCheckpointPath(spec *specs.Spec) string {
	return spec.Annotations[annotationFSCheckpointPath]
}

// GetAnnotationFSCheckpointDirect returns true if filesystem checkpoint I/O
// controlled by the containing annotation should use O_DIRECT.
func GetAnnotationFSCheckpointDirect(spec *specs.Spec) bool {
	return specutils.AnnotationToBool(spec, annotationFSCheckpointDirect)
}

// GetAnnotationFSCheckpointPaths returns the filesystem checkpoint target paths
// specified in the container annotation.
func GetAnnotationFSCheckpointPaths(spec *specs.Spec) []string {
	annot := spec.Annotations[annotationFSCheckpointPaths]
	if annot == "" {
		return nil
	}
	return strings.Split(annot, ",")
}

// FSSave implements kernel.Saver.FSSave.
//
// +checklocksexclude:l.mu
// +checklocksexclude:l.k.fsSaveMu
func (l *Loader) FSSave() error {
	l.mu.Lock()
	fsSaveFDs := l.fsSaveFDs
	l.fsSaveFDs = nil
	useCheckpointGofer := l.fsSaveCheckpointGofer
	l.mu.Unlock()
	if len(fsSaveFDs) == 0 {
		return linuxerr.ENXIO
	}
	args := FSSaveArgs{
		ExitAfterSaving: !specutils.AnnotationToBool(l.root.spec, annotationFSCheckpointResume),
		Paths:           GetAnnotationFSCheckpointPaths(l.root.spec),
	}
	args.FilePayload.Files = fd.ReleaseToFiles(fsSaveFDs, "fs-checkpoint")
	defer func() {
		for _, f := range args.FilePayload.Files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	args.UseCheckpointGofer = useCheckpointGofer
	opts, err := convertToKernelFSSaveOpts(&args)
	if err != nil {
		return err
	}
	return l.k.FSSave(context.Background(), &opts)
}

func convertToKernelFSSaveOpts(args *FSSaveArgs) (kernel.FSSaveOpts, error) {
	bundles, err := fscheckpoint.ParseBundles(args.Paths)
	if err != nil {
		return kernel.FSSaveOpts{}, err
	}
	if len(bundles) == 0 {
		bundles = []fscheckpoint.Bundle{{}}
	}
	opts := kernel.FSSaveOpts{
		RunscVersion:    version.Version(),
		ExitAfterSaving: args.ExitAfterSaving,
		Prefix:          bundles[0].Prefix,
		Paths:           bundles[0].Paths,
		FSBundles:       make([]kernel.FSSaveOpts, len(bundles)-1),
	}
	for i, b := range bundles[1:] {
		opts.FSBundles[i] = kernel.FSSaveOpts{
			Prefix: b.Prefix,
			Paths:  b.Paths,
		}
	}
	if err := setKernelFSSaveOptsFiles(args, bundles, &opts); err != nil {
		_ = opts.Close()
		return kernel.FSSaveOpts{}, err
	}
	return opts, nil
}

func setKernelFSSaveOptsFiles(args *FSSaveArgs, bundles []fscheckpoint.Bundle, opts *kernel.FSSaveOpts) error {
	if args.UseCheckpointGofer {
		return setKernelFSSaveOptsFilesForCheckpointGofer(args, bundles, opts)
	}
	if len(args.FilePayload.Files) != 4*len(bundles) {
		return fmt.Errorf("got %d files, want %d", len(args.FilePayload.Files), 4*len(bundles))
	}
	if err := setKernelFSSaveOptsFilesForLocalCheckpoint(args, 0, opts); err != nil {
		return err
	}
	for i := range opts.FSBundles {
		if err := setKernelFSSaveOptsFilesForLocalCheckpoint(args, 4*(i+1), &opts.FSBundles[i]); err != nil {
			return err
		}
	}
	return nil
}

func setKernelFSSaveOptsFilesForLocalCheckpoint(args *FSSaveArgs, offset int, opts *kernel.FSSaveOpts) error {
	manifestFile, err := args.ReleaseFD(offset)
	if err != nil {
		return err
	}
	multiTarFile, err := args.ReleaseFD(offset + 1)
	if err != nil {
		manifestFile.Close()
		return err
	}
	pagesMetadataFile, err := args.ReleaseFD(offset + 2)
	if err != nil {
		manifestFile.Close()
		multiTarFile.Close()
		return err
	}
	pagesFile, err := args.ReleaseFD(offset + 3)
	if err != nil {
		manifestFile.Close()
		multiTarFile.Close()
		pagesMetadataFile.Close()
		return err
	}
	opts.ManifestFile = stateio.NewBufioWriteCloser(manifestFile)
	opts.MultiTarFile = stateio.NewBufioWriteCloser(multiTarFile)
	opts.PagesMetadataFile = stateio.NewBufioWriteCloser(pagesMetadataFile)
	opts.PagesFile = stateio.NewPagesFileFDWriterDefault(int32(pagesFile.Release()))
	return nil
}

func setKernelFSSaveOptsFilesForCheckpointGofer(args *FSSaveArgs, bundles []fscheckpoint.Bundle, opts *kernel.FSSaveOpts) error {
	if fscheckpoint.HasPrefixes(bundles) {
		return fmt.Errorf("multi-bundle or prefixed filesystem checkpoint is not supported with checkpoint gofer")
	}
	clientFD, err := unix.Dup(int(args.Files[0].Fd()))
	if err != nil {
		return fmt.Errorf("failed to dup checkpoint gofer client FD: %w", err)
	}
	clientSock, err := unet.NewSocket(clientFD)
	if err != nil {
		unix.Close(clientFD)
		return fmt.Errorf("failed to create unet.Socket for checkpoint gofer client FD: %w", err)
	}
	afc, err := stateipc.NewAsyncFileClient(urpc.NewClient(clientSock) /* transfers ownership */)
	if err != nil {
		return fmt.Errorf("failed to create stateipc client: %w", err)
	}
	defer afc.DecRef()

	manifestFileAsync, err := afc.OpenWrite(checkpointfiles.FSCheckpointManifestFileName)
	if err != nil {
		return fmt.Errorf("failed to open manifest file: %w", err)
	}
	manifestFile, err := stateio.NewBufWriter(manifestFileAsync /* transfers ownership */, 2<<20 /* size = 2 MiB */)
	if err != nil {
		return fmt.Errorf("failed to buffer manifest file: %w", err)
	}
	closeCleanup := cleanup.Make(func() { manifestFile.Close() })
	defer closeCleanup.Clean()

	multiTarFileAsync, err := afc.OpenWrite(checkpointfiles.FSCheckpointMultiTarFileName)
	if err != nil {
		return fmt.Errorf("failed to open multi-tar file: %w", err)
	}
	multiTarFile, err := stateio.NewBufWriter(multiTarFileAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		return fmt.Errorf("failed to buffer multi-tar file: %w", err)
	}
	closeCleanup.Add(func() { multiTarFile.Close() })

	pagesMetadataFileAsync, err := afc.OpenWrite(checkpointfiles.PagesMetadataFileName)
	if err != nil {
		return fmt.Errorf("failed to open pages metadata file: %w", err)
	}
	pagesMetadataFile, err := stateio.NewBufWriter(pagesMetadataFileAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		return fmt.Errorf("failed to buffer pages metadata file: %w", err)
	}
	closeCleanup.Add(func() { pagesMetadataFile.Close() })

	pagesFile, err := afc.OpenWrite(checkpointfiles.PagesFileName)
	if err != nil {
		return fmt.Errorf("failed to open pages file: %w", err)
	}

	closeCleanup.Release()
	opts.ManifestFile = manifestFile
	opts.MultiTarFile = multiTarFile
	opts.PagesMetadataFile = pagesMetadataFile
	opts.PagesFile = pagesFile
	return nil
}

// fsRestoreBundle holds the state of a single filesystem checkpoint bundle.
type fsRestoreBundle struct {
	// immutable
	getPagesMetadata func() ([]byte, error)
	getMultiTar      func() ([]byte, error)

	// immutable after fsRestore.wg.Wait()
	apfl *pgalloc.AsyncPagesFileLoad
}

// fsRestore holds the state of a filesystem restore.
type fsRestore struct {
	wg sync.WaitGroup

	// immutable after wg.Wait()
	manifestErr error
	mfs         map[checkpoint.ResourceID]*fscheckpoint.MemoryFile
	tmpfs       map[checkpoint.ResourceID]*fscheckpoint.Tmpfs
	fsBundles   map[checkpoint.ResourceID]*fsRestoreBundle

	waitMu sync.Mutex

	// waitMap tracks restore completion by container ID.
	//
	// +checklocks:waitMu
	waitMap map[string]*fsRestoreContainer

	// +checklocks:waitMu
	claimedMFs map[checkpoint.ResourceID]struct{}

	// +checklocks:waitMu
	claimedTmpfs map[checkpoint.ResourceID]struct{}

	// stateRestore is true during full sentry state restore (runsc restore),
	// where tmpfs trees are restored from the sentry state file rather than
	// via tmpfsSourceTar.
	//
	// +checklocks:waitMu
	stateRestore bool
}

type fsRestoreContainer struct {
	// containerName is the container name from the checkpoint ResourceID.
	containerName string

	// err is the first error encountered while restoring this container.
	//
	// +checklocks:cond.L
	err error

	// asyncLoads counts MemoryFiles currently in async page loading.
	//
	// +checklocks:cond.L
	asyncLoads int

	// cond wakes waiters when an error occurs or all async loads complete.
	// ensureContainer sets L to the owning fsRestore's waitMu before
	// publishing the entry in waitMap; L is not reassigned afterwards.
	cond sync.Cond
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

func makeFSRestoreOpts(args *Args) ([]fsRestoreOpts, error) {
	if args.FSRestoreCheckpointGofer {
		opt, err := makeFSRestoreOptsForCheckpointGofer(args)
		if err != nil {
			return nil, err
		}
		return []fsRestoreOpts{opt}, nil
	}
	return makeFSRestoreOptsForLocalCheckpoint(args)
}

func makeFSRestoreOptsForLocalCheckpoint(args *Args) ([]fsRestoreOpts, error) {
	if len(args.FSRestoreFDs) == 0 || len(args.FSRestoreFDs)%4 != 0 {
		return nil, fmt.Errorf("got %d files in -fs-restore-fds, want a positive multiple of 4", len(args.FSRestoreFDs))
	}
	opts := make([]fsRestoreOpts, len(args.FSRestoreFDs)/4)
	for i := range opts {
		offset := 4 * i
		opts[i] = fsRestoreOpts{
			ManifestFile:      stateio.NewBufioReadCloser(args.FSRestoreFDs[offset].ReleaseToFile(checkpointfiles.FSCheckpointManifestFileName)),
			MultiTarFile:      stateio.NewBufioReadCloser(args.FSRestoreFDs[offset+1].ReleaseToFile(checkpointfiles.FSCheckpointMultiTarFileName)),
			PagesMetadataFile: stateio.NewBufioReadCloser(args.FSRestoreFDs[offset+2].ReleaseToFile(checkpointfiles.PagesMetadataFileName)),
			PagesFile:         stateio.NewPagesFileFDReaderDefault(int32(args.FSRestoreFDs[offset+3].Release())),
		}
	}
	return opts, nil
}

func makeFSRestoreOptsForCheckpointGofer(args *Args) (fsRestoreOpts, error) {
	if len(args.FSRestoreFDs) != 1 {
		return fsRestoreOpts{}, fmt.Errorf("got %d files in -fs-restore-fds, want 1", len(args.FSRestoreFDs))
	}
	clientFD := args.FSRestoreFDs[0].Release()
	clientSock, err := unet.NewSocket(clientFD)
	if err != nil {
		unix.Close(clientFD)
		return fsRestoreOpts{}, fmt.Errorf("failed to create unet.Socket for checkpoint gofer client FD: %w", err)
	}
	afc, err := stateipc.NewAsyncFileClient(urpc.NewClient(clientSock) /* transfers ownership */)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to create stateipc client: %w", err)
	}
	defer afc.DecRef()

	manifestFileAsync, err := afc.OpenRead(checkpointfiles.FSCheckpointManifestFileName)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to open manifest file: %w", err)
	}
	manifestFile, err := stateio.NewBufReader(manifestFileAsync /* transfers ownership */, 2<<20 /* size = 2 MiB */)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to buffer manifest file: %w", err)
	}
	closeCleanup := cleanup.Make(func() { manifestFile.Close() })
	defer closeCleanup.Clean()

	multiTarFileAsync, err := afc.OpenRead(checkpointfiles.FSCheckpointMultiTarFileName)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to open multi-tar file: %w", err)
	}
	multiTarFile, err := stateio.NewBufReader(multiTarFileAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to buffer multi-tar file: %w", err)
	}
	closeCleanup.Add(func() { multiTarFile.Close() })

	pagesMetadataFileAsync, err := afc.OpenRead(checkpointfiles.PagesMetadataFileName)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to open pages metadata file: %w", err)
	}
	pagesMetadataFile, err := stateio.NewBufReader(pagesMetadataFileAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to buffer pages metadata file: %w", err)
	}
	closeCleanup.Add(func() { pagesMetadataFile.Close() })

	pagesFile, err := afc.OpenRead(checkpointfiles.PagesFileName)
	if err != nil {
		return fsRestoreOpts{}, fmt.Errorf("failed to open pages file: %w", err)
	}

	closeCleanup.Release()
	return fsRestoreOpts{
		ManifestFile:      manifestFile,
		MultiTarFile:      multiTarFile,
		PagesMetadataFile: pagesMetadataFile,
		PagesFile:         pagesFile,
	}, nil
}

// startFSRestore takes ownership of resources in optsList.
func startFSRestore(optsList []fsRestoreOpts) (*fsRestore, error) {
	fsr := &fsRestore{
		mfs:          make(map[checkpoint.ResourceID]*fscheckpoint.MemoryFile),
		tmpfs:        make(map[checkpoint.ResourceID]*fscheckpoint.Tmpfs),
		fsBundles:    make(map[checkpoint.ResourceID]*fsRestoreBundle),
		waitMap:      make(map[string]*fsRestoreContainer),
		claimedMFs:   make(map[checkpoint.ResourceID]struct{}),
		claimedTmpfs: make(map[checkpoint.ResourceID]struct{}),
	}

	// TODO: NOLINT - Currently we read the whole pages metadata file into a
	// []byte, then pass pieces of that []byte to MemoryFile construction. This
	// is necessary because opts.PagesMetadataFile is io.Reader (read
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
	//
	// TODO(b/541219576): Instead of reading the full tar file into memory and
	// retaining it via readOnce for the lifetime of the sandbox, read using
	// offsets in the multi-tar file using TarStart and TarEnd from manifest,
	// or release the cached multiTar slice once restore completes.
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

	bundles := make([]*fsRestoreBundle, len(optsList))
	for i := range optsList {
		bundles[i] = &fsRestoreBundle{
			getPagesMetadata: readOnce("pages metadata file", &optsList[i].PagesMetadataFile),
			getMultiTar:      readOnce("multi-tar file", &optsList[i].MultiTarFile),
		}
	}

	// Read and handle the manifests in parallel.
	fsr.manifestErr = fmt.Errorf("loading manifest panicked")
	fsr.wg.Go(func() {
		defer func() {
			for i := range optsList {
				if optsList[i].ManifestFile != nil {
					optsList[i].ManifestFile.Close()
					optsList[i].ManifestFile = nil
				}
				if optsList[i].PagesFile != nil {
					optsList[i].PagesFile.Close()
					optsList[i].PagesFile = nil
				}
			}
			if fsr.manifestErr != nil {
				for _, b := range bundles {
					if b.apfl != nil {
						b.apfl.MemoryFilesDone()
					}
				}
			}
		}()
		loadBundle := func(opts *fsRestoreOpts, bundle *fsRestoreBundle) error {
			var manifest fscheckpoint.Manifest
			timeStart := time.Now()
			manifestData, err := io.ReadAll(opts.ManifestFile)
			if err != nil {
				return fmt.Errorf("failed to read manifest: %w", err)
			}
			var pb fspb.Manifest
			if err := proto.Unmarshal(manifestData, &pb); err != nil {
				return fmt.Errorf("failed to decode proto manifest: %w", err)
			}
			manifest = fscheckpoint.FromProto(&pb)
			log.Infof("Read filesystem checkpoint manifest in %s", time.Since(timeStart))
			if manifest.Version > 1 {
				return fmt.Errorf("unsupported filesystem checkpoint version: %d", manifest.Version)
			}
			log.Infof("Restoring from proto manifest (version %d) created by runsc version %q", manifest.Version, manifest.RunscVersion)
			if manifest.PageSize != hostarch.PageSize {
				return fmt.Errorf("filesystem checkpoint page size %d does not match current page size %d", manifest.PageSize, hostarch.PageSize)
			}
			if endian := hostarch.EndianString(); manifest.Endian != endian {
				return fmt.Errorf("filesystem checkpoint endianness %q does not match current endianness %q", manifest.Endian, endian)
			}

			for i := range manifest.MemoryFiles {
				mmf := &manifest.MemoryFiles[i]
				if err := addRestoreEntry(fsr.mfs, fsr.fsBundles, mmf.ResourceID, mmf, bundle, "MemoryFile"); err != nil {
					return err
				}
			}
			for i := range manifest.Tmpfs {
				mt := &manifest.Tmpfs[i]
				if err := addRestoreEntry(fsr.tmpfs, fsr.fsBundles, mt.ResourceID, mt, bundle, "Tmpfs"); err != nil {
					return err
				}
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
			bundle.apfl = apfl
			// Note that apfl.MemoryFilesDone() will never be called on success.
			// This is because if a container fails and is restarted, we also want
			// to restore the filesystem of the restarted container, so we need to
			// keep filesystem restore operational indefinitely.
			return nil
		}
		for i := range optsList {
			if err := loadBundle(&optsList[i], bundles[i]); err != nil {
				fsr.manifestErr = fmt.Errorf("bundle %d: %w", i, err)
				return
			}
		}
		fsr.manifestErr = nil
	})

	return fsr, nil
}

func addRestoreEntry[T any](m map[checkpoint.ResourceID]T, fsBundles map[checkpoint.ResourceID]*fsRestoreBundle, id checkpoint.ResourceID, val T, bundle *fsRestoreBundle, typeName string) error {
	if _, ok := m[id]; ok {
		return fmt.Errorf("duplicate %s ResourceID %q in filesystem checkpoint", typeName, id)
	}
	if existing := fsBundles[id]; existing != nil && existing != bundle {
		return fmt.Errorf("ResourceID %q appears in multiple filesystem checkpoint bundles", id)
	}
	m[id] = val
	if fsBundles != nil && bundle != nil {
		fsBundles[id] = bundle
	}
	return nil
}

// +checklocksexclude:fsr.waitMu
func (fsr *fsRestore) markStateRestore() {
	if fsr == nil {
		return
	}
	fsr.waitMu.Lock()
	defer fsr.waitMu.Unlock()
	fsr.stateRestore = true
}

// +checklocks:fsr.waitMu
func (fsr *fsRestore) ensureContainer(cid, containerName string) *fsRestoreContainer {
	c := fsr.waitMap[cid]
	if c == nil {
		c = &fsRestoreContainer{containerName: containerName}
		c.cond.L = &fsr.waitMu
		fsr.waitMap[cid] = c
	}
	return c
}

// setError records the first non-nil error and wakes waiters, returning err.
//
// +checklocks:c.cond.L
func (c *fsRestoreContainer) setError(err error) error {
	if c.err == nil && err != nil {
		c.err = err
		c.cond.Broadcast()
	}
	return err
}

// findByResourceID looks up a resource by exact ResourceID (ContainerName + Path).
// If exact match fails, it attempts to match by Path alone as a fallback when
// either the requested ID or the checkpointed entry has an empty ContainerName
// (e.g. single-container vs multi-container checkpoint compatibility). Conflicting
// non-empty container names are never matched across containers.
// If multiple entries match the path fallback ambiguously, an error is returned.
// findByResourceID is called at restore time for resource lookup.
func findByResourceID[T any](m map[checkpoint.ResourceID]T, id checkpoint.ResourceID, getResourceID func(T) checkpoint.ResourceID, typeName string) (T, bool, error) {
	if val, ok := m[id]; ok {
		return val, true, nil
	}
	var (
		match T
		found bool
	)
	for valID, val := range m {
		matchingContainer := id.ContainerName == valID.ContainerName || id.ContainerName == "" || valID.ContainerName == ""
		if valID.Path == id.Path && matchingContainer {
			if found {
				var zero T
				return zero, false, fmt.Errorf("ambiguous %s match for ResourceID %v (matches both %v and %v)", typeName, id, getResourceID(match), valID)
			}
			match = val
			found = true
		}
	}
	if found {
		log.Debugf("fsRestore: mapped %s ResourceID %v to %v by path matching", typeName, id, getResourceID(match))
		return match, true, nil
	}
	var zero T
	return zero, false, nil
}

func (fsr *fsRestore) bundleFor(id checkpoint.ResourceID) (*fsRestoreBundle, error) {
	b := fsr.fsBundles[id]
	if b == nil {
		return nil, fmt.Errorf("no restore bundle mapped for ResourceID %q", id)
	}
	return b, nil
}

// +checklocksexclude:fsr.waitMu
func (fsr *fsRestore) memoryFileLoadArgs(id checkpoint.ResourceID, cid string) (io.Reader, *pgalloc.LoadOpts, error) {
	if fsr == nil {
		return nil, nil, nil
	}

	fsr.wg.Wait()
	if fsr.manifestErr != nil {
		return nil, nil, fsr.manifestErr
	}
	mmf, ok, err := findByResourceID(fsr.mfs, id, func(m *fscheckpoint.MemoryFile) checkpoint.ResourceID {
		return m.ResourceID
	}, "MemoryFile")
	if err != nil {
		fsr.waitMu.Lock()
		defer fsr.waitMu.Unlock()
		c := fsr.ensureContainer(cid, id.ContainerName)
		// ensureContainer binds c.cond.L to the held fsr.waitMu. checklocks
		// cannot recover that identity from the returned entry.
		return nil, nil, c.setError(err) // +checklocksignore
	}
	if !ok {
		return nil, nil, nil
	}
	bundle, err := fsr.bundleFor(mmf.ResourceID)
	if err != nil {
		fsr.waitMu.Lock()
		defer fsr.waitMu.Unlock()
		c := fsr.ensureContainer(cid, id.ContainerName)
		return nil, nil, c.setError(err) // +checklocksignore
	}
	pagesMetadata, err := bundle.getPagesMetadata()

	fsr.waitMu.Lock()
	defer fsr.waitMu.Unlock()
	c := fsr.ensureContainer(cid, id.ContainerName)
	// ensureContainer binds c.cond.L to the held fsr.waitMu. checklocks
	// cannot recover that identity from the returned entry.
	if err != nil {
		return nil, nil, c.setError(fmt.Errorf("failed to read pages metadata: %w", err)) // +checklocksignore
	}
	if mmf.PagesMetadataStart > mmf.PagesMetadataEnd || mmf.PagesMetadataEnd > uint64(len(pagesMetadata)) {
		return nil, nil, c.setError(fmt.Errorf("MemoryFile %q has invalid pages metadata range [%d, %d) for file size %d", mmf.ResourceID, mmf.PagesMetadataStart, mmf.PagesMetadataEnd, len(pagesMetadata))) // +checklocksignore
	}
	if mmf.PagesStart%hostarch.PageSize != 0 {
		return nil, nil, c.setError(fmt.Errorf("MemoryFile %q pages offset %d is not page-aligned (page size %d)", mmf.ResourceID, mmf.PagesStart, hostarch.PageSize)) // +checklocksignore
	}
	fsr.claimedMFs[mmf.ResourceID] = struct{}{}
	c.asyncLoads++ // +checklocksignore
	return bytes.NewReader(pagesMetadata[mmf.PagesMetadataStart:mmf.PagesMetadataEnd]), &pgalloc.LoadOpts{
		PagesFile:       bundle.apfl,
		PagesFileOffset: mmf.PagesStart,
		DoneCallback: func(err error) {
			fsr.waitMu.Lock()
			defer fsr.waitMu.Unlock()
			// The captured entry still uses fsr.waitMu as c.cond.L; checklocks
			// cannot relate that interface value to the lock acquired above.
			c.asyncLoads-- // +checklocksignore
			switch {
			case err != nil:
				if c.err == nil { // +checklocksignore
					c.err = err // +checklocksignore
				}
				fallthrough
			case c.asyncLoads == 0: // +checklocksignore
				c.cond.Broadcast()
			}
		},
	}, nil
}

// +checklocksexclude:fsr.waitMu
func (fsr *fsRestore) tmpfsSourceTar(id checkpoint.ResourceID, cid string) (io.ReadCloser, error) {
	if fsr == nil {
		return nil, nil
	}

	fsr.wg.Wait()
	if fsr.manifestErr != nil {
		return nil, fsr.manifestErr
	}
	mt, ok, err := findByResourceID(fsr.tmpfs, id, func(t *fscheckpoint.Tmpfs) checkpoint.ResourceID {
		return t.ResourceID
	}, "Tmpfs")
	if err != nil {
		fsr.waitMu.Lock()
		defer fsr.waitMu.Unlock()
		c := fsr.ensureContainer(cid, id.ContainerName)
		// ensureContainer binds c.cond.L to the held fsr.waitMu. checklocks
		// cannot recover that identity from the returned entry.
		return nil, c.setError(err) // +checklocksignore
	}
	if !ok {
		return nil, nil
	}
	bundle, err := fsr.bundleFor(mt.ResourceID)
	if err != nil {
		fsr.waitMu.Lock()
		defer fsr.waitMu.Unlock()
		c := fsr.ensureContainer(cid, id.ContainerName)
		return nil, c.setError(err) // +checklocksignore
	}
	multiTar, err := bundle.getMultiTar()

	fsr.waitMu.Lock()
	defer fsr.waitMu.Unlock()
	c := fsr.ensureContainer(cid, id.ContainerName)
	// ensureContainer binds c.cond.L to the held fsr.waitMu. checklocks
	// cannot recover that identity from the returned entry.
	if err != nil {
		return nil, c.setError(fmt.Errorf("failed to read tar archive: %w", err)) // +checklocksignore
	}
	if mt.TarStart > mt.TarEnd || mt.TarEnd > uint64(len(multiTar)) {
		return nil, c.setError(fmt.Errorf("tmpfs %q has invalid tar range [%d, %d) for multi-tar file size %d", mt.ResourceID, mt.TarStart, mt.TarEnd, len(multiTar))) // +checklocksignore
	}
	fsr.claimedTmpfs[mt.ResourceID] = struct{}{}
	return io.NopCloser(bytes.NewReader(multiTar[mt.TarStart:mt.TarEnd])), nil
}

// wait blocks until either all filesystems have been restored for the
// container with the given ID, or an error occurs while restoring filesystems
// for that container.
//
// +checklocksexclude:fsr.waitMu
func (fsr *fsRestore) wait(cid string) error {
	if fsr == nil {
		return fmt.Errorf("filesystem restore is not enabled")
	}
	fsr.wg.Wait()
	if fsr.manifestErr != nil {
		return fsr.manifestErr
	}
	fsr.waitMu.Lock()
	defer fsr.waitMu.Unlock()
	c := fsr.waitMap[cid]
	if c == nil {
		return fmt.Errorf("no filesystems restored for container %s", cid)
	}
	// Entries are published with c.cond.L bound to fsr.waitMu. checklocks
	// cannot recover that identity through the waitMap lookup.
	for {
		if c.err != nil { // +checklocksignore
			return c.err // +checklocksignore
		}
		if c.asyncLoads == 0 { // +checklocksignore
			matchesContainer := func(id checkpoint.ResourceID) bool {
				return id.ContainerName == c.containerName || id.ContainerName == "" || c.containerName == ""
			}
			for id := range fsr.mfs {
				if matchesContainer(id) {
					if _, ok := fsr.claimedMFs[id]; !ok {
						log.Warningf("Filesystem checkpoint MemoryFile %v was not claimed by any mount", id)
					}
				}
			}
			if !fsr.stateRestore {
				for id := range fsr.tmpfs {
					if matchesContainer(id) {
						if _, ok := fsr.claimedTmpfs[id]; !ok {
							log.Warningf("Filesystem checkpoint Tmpfs %v was not claimed by any mount", id)
						}
					}
				}
			}
			return nil
		}
		c.cond.Wait()
	}
}
