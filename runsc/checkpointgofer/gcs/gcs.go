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

// Package gcs provides support for state files stored in Google Cloud Storage.
package gcs

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/oauth2adapt"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	numMiscFiles = 2 // true for both kernel and filesystem checkpoints

	// Read tuning parameters:
	manifestFileMaxReadBytes    = 1 << 20 // 1 MiB
	manifestFileMaxReadParallel = 2
	miscFileMaxReadBytes        = 1 << 20 // 1 MiB
	miscFileMaxReadParallel     = 8
	pagesFileMaxReadBytes       = 16 << 20 // 16 MiB
	pagesFileMaxReadParallel    = 160

	// Write tuning parameters:
	manifestFileMaxWriteBytes    = 2 << 20 // 2 MiB
	manifestFileMaxWriteParallel = 2
	miscFileMaxWriteBytes        = 2 << 20 // 2 MiB
	miscFileMaxWriteParallel     = 4
	pagesFileMaxWriteBytes       = 32 << 20 // 32 MiB
	pagesFileMaxWriteParallel    = 4
	pagesFileMaxPCUWriteParallel = 160

	// contentType is the Content-Type for all GCS objects created by this
	// package.
	contentType = "application/octet-stream"
)

// FileServer implements stateipc.AsyncFileServerImpl for reading checkpoint
// files from GCS.
type FileServer struct {
	ctx                     context.Context
	client                  *storage.Client
	allowCheckpointReads    bool
	allowCheckpointWrites   bool
	allowFSCheckpointReads  bool
	allowFSCheckpointWrites bool
	pcuMode                 ParallelCompositeUploadMode
	bucket                  *storage.BucketHandle
	objectPrefix            string
	cancel                  context.CancelCauseFunc

	background sync.WaitGroup

	// Only used if allowWrites == true:
	pcuEnabledOnce sync.Once
	pcuEnabled     bool
}

// FileServerOptions provides options to NewFileServer.
type FileServerOptions struct {
	// AllowCheckpointReads enables checkpoint reading.
	AllowCheckpointReads bool

	// AllowCheckpointWrites enables checkpoint writing.
	AllowCheckpointWrites bool

	// AllowFSCheckpointReads enables filesystem checkpoint reading.
	AllowFSCheckpointReads bool

	// AllowFSCheckpointWrites enables filesystem checkpoint writing.
	AllowFSCheckpointWrites bool

	// If TokenSource is not nil, it provides authentication tokens. Otherwise,
	// application default credentials will be used.
	TokenSource oauth2.TokenSource

	// Bucket is the name of the GCS bucket.
	Bucket string

	// ObjectPrefix is prepended to each filename to form GCS object names.
	ObjectPrefix string

	// ParallelCompositeUpload controls whether parallel composite upload is
	// used for writing the pages file.
	ParallelCompositeUpload ParallelCompositeUploadMode
}

// ParallelCompositeUploadMode is the type of
// FileServerOptions.ParallelCompositeUpload.
type ParallelCompositeUploadMode uint8

const (
	// ParallelCompositeUploadSafe enables parallel composite upload if doing
	// so will not create undeletable temporary objects, incur early deletion
	// fees, or cause the created object to have a non-default storage class,
	// as described by
	// https://cloud.google.com/storage/docs/parallel-composite-uploads.
	//
	// Note that parallel composite upload will unavoidably incur additional
	// operation charges for writes to temporary objects, as well as
	// composition of objects.
	ParallelCompositeUploadSafe ParallelCompositeUploadMode = iota

	// ParallelCompositeUploadDisable disables parallel composite upload.
	ParallelCompositeUploadDisable

	// ParallelCompositeUploadForce enables parallel composite upload without
	// checking if bucket attributes prevent, or incur additional costs on,
	// temporary object storage or deletion.
	ParallelCompositeUploadForce
)

// NewFileServer returns a new FileServer.
func NewFileServer(ctx context.Context, opts *FileServerOptions) (*FileServer, error) {
	if len(opts.Bucket) == 0 {
		return nil, fmt.Errorf("GCS bucket must be specified")
	}

	var (
		authOpts []option.ClientOption
		tokenSrc oauth2.TokenSource
	)
	if opts.TokenSource != nil {
		authOpts = []option.ClientOption{option.WithTokenSource(opts.TokenSource)}
		tokenSrc = opts.TokenSource
	} else {
		// Note that there is no devstorage.write_only scope:
		// https://developers.google.com/identity/protocols/oauth2/scopes#storage
		scope := "https://www.googleapis.com/auth/devstorage.read_only"
		if opts.AllowCheckpointWrites || opts.AllowFSCheckpointWrites {
			scope = "https://www.googleapis.com/auth/devstorage.read_write"
		}
		cred, err := credentials.DetectDefault(&credentials.DetectOptions{
			Scopes: []string{scope},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to obtain default credentials: %w", err)
		}
		domain, err := cred.UniverseDomain(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain universe domain: %w", err)
		}
		authOpts = []option.ClientOption{
			option.WithUniverseDomain(domain),
			option.WithAuthCredentials(cred),
		}
		tokenSrc = oauth2adapt.TokenSourceFromTokenProvider(cred.TokenProvider)
	}

	maxParallelTotal := 0
	if opts.AllowCheckpointReads || opts.AllowFSCheckpointReads {
		maxParallelRead := numMiscFiles*miscFileMaxReadParallel + pagesFileMaxReadParallel
		if opts.AllowFSCheckpointReads {
			maxParallelRead += manifestFileMaxReadParallel
		}
		maxParallelTotal = max(maxParallelTotal, maxParallelRead)
	}
	if opts.AllowCheckpointWrites || opts.AllowFSCheckpointWrites {
		maxParallelWrite := numMiscFiles * miscFileMaxWriteParallel
		if opts.AllowFSCheckpointWrites {
			maxParallelWrite += manifestFileMaxWriteParallel
		}
		switch opts.ParallelCompositeUpload {
		case ParallelCompositeUploadDisable:
			maxParallelWrite += pagesFileMaxWriteParallel
		case ParallelCompositeUploadForce:
			maxParallelWrite += pagesFileMaxPCUWriteParallel
		default:
			maxParallelWrite += max(pagesFileMaxWriteParallel, pagesFileMaxPCUWriteParallel)
		}
		maxParallelTotal = max(maxParallelTotal, maxParallelWrite)
	}

	client, err := storage.NewClient(ctx, append(authOpts,
		// The gRPC client does not support storage.Writer.ChunkSize == 0 and
		// forces a minimum of 256 KiB, which is problematic for
		// ParallelWriter. See ParallelWriter.writerMain for details.
		// Consequently, we must use the HTTP client, at least if parallel
		// composite upload is enabled.
		option.WithHTTPClient(&http.Client{
			Transport: &oauth2.Transport{
				Base: &http.Transport{
					MaxIdleConnsPerHost: maxParallelTotal,
					// Disable HTTP/2 for performance, consistent with gcsfuse.
					TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
				},
				Source: tokenSrc,
			},
		}),
		// This is recommended by storage.NewClient's documentation.
		storage.WithJSONReads())...)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	s := &FileServer{
		ctx:                     ctx,
		client:                  client,
		allowCheckpointReads:    opts.AllowCheckpointReads,
		allowCheckpointWrites:   opts.AllowCheckpointWrites,
		allowFSCheckpointReads:  opts.AllowFSCheckpointReads,
		allowFSCheckpointWrites: opts.AllowFSCheckpointWrites,
		pcuMode:                 opts.ParallelCompositeUpload,
		bucket:                  client.Bucket(opts.Bucket),
		objectPrefix:            opts.ObjectPrefix,
		cancel:                  cancel,
	}
	if s.allowCheckpointWrites || s.allowFSCheckpointWrites {
		s.background.Add(1)
		go func() {
			defer s.background.Done()
			s.getParallelCompositeUploadEnabled()
		}()
	}
	return s, nil
}

// Destroy implements stateipc.AsyncFileServerImpl.Destroy.
func (s *FileServer) Destroy() {
	s.cancel(fmt.Errorf("context canceled by gcs.FileServer.Destroy"))
	s.background.Wait()
	s.client.Close()
}

// OpenRead implements stateipc.AsyncFileServerImpl.OpenRead.
func (s *FileServer) OpenRead(path string) (stateio.AsyncReader, error) {
	// Files other than the pages file are read using stateio.BufReader, which
	// doesn't use MaxRanges > 1.
	switch path {
	case checkpointfiles.StateFileName:
		if !s.allowCheckpointReads {
			log.Warningf("gcs.FileServer.OpenRead: attempted to open %q with allowCheckpointReads disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for reading", s.bucket.BucketName(), obj.ObjectName())
		return NewReader(s.ctx, obj, miscFileMaxReadBytes, 1 /* maxRanges */, miscFileMaxReadParallel), nil

	case checkpointfiles.FSCheckpointManifestFileName:
		if !s.allowFSCheckpointReads {
			log.Warningf("gcs.FileServer.OpenRead: attempted to open %q with allowFSCheckpointReads disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for reading", s.bucket.BucketName(), obj.ObjectName())
		return NewReader(s.ctx, obj, manifestFileMaxReadBytes, 1 /* maxRanges */, manifestFileMaxReadParallel), nil

	case checkpointfiles.FSCheckpointMultiTarFileName:
		if !s.allowFSCheckpointReads {
			log.Warningf("gcs.FileServer.OpenRead: attempted to open %q with allowFSCheckpointReads disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for reading", s.bucket.BucketName(), obj.ObjectName())
		return NewReader(s.ctx, obj, miscFileMaxReadBytes, 1 /* maxRanges */, miscFileMaxReadParallel), nil

	case checkpointfiles.PagesMetadataFileName:
		if !s.allowCheckpointReads && !s.allowFSCheckpointReads {
			log.Warningf("gcs.FileServer.OpenRead: attempted to open %q with allowCheckpointReads and allowFSCheckpointReads disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for reading", s.bucket.BucketName(), obj.ObjectName())
		return NewReader(s.ctx, obj, miscFileMaxReadBytes, 1 /* maxRanges */, miscFileMaxReadParallel), nil

	case checkpointfiles.PagesFileName:
		if !s.allowCheckpointReads && !s.allowFSCheckpointReads {
			log.Warningf("gcs.FileServer.OpenRead: attempted to open %q with allowCheckpointReads and allowFSCheckpointReads disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for reading", s.bucket.BucketName(), obj.ObjectName())
		// Provision one range per page, which is the most that
		// pgalloc.MemoryFile restore can require. Since Reader doesn't (can't)
		// use readv, we aren't subject to UIO_MAXIOV.
		maxRanges := pagesFileMaxReadBytes / os.Getpagesize()
		return NewReader(s.ctx, obj, pagesFileMaxReadBytes, maxRanges, pagesFileMaxReadParallel), nil

	default:
		log.Warningf("gcs.FileServer.OpenRead: unknown path %q", path)
		return nil, fs.ErrPermission
	}
}

// OpenWrite implements stateipc.AsyncFileServerImpl.OpenWrite.
func (s *FileServer) OpenWrite(path string) (stateio.AsyncWriter, error) {
	// Files other than the pages file are written using stateio.BufWriter,
	// which doesn't use MaxRanges > 1, and are expected to be too small to
	// benefit from parallel composite upload.
	switch path {
	case checkpointfiles.StateFileName:
		if !s.allowCheckpointWrites {
			log.Warningf("gcs.FileServer.OpenWrite: attempted to open %q with allowCheckpointWrites disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for writing", s.bucket.BucketName(), obj.ObjectName())
		return NewWriter(s.ctx, obj, miscFileMaxWriteBytes, 1 /* maxRanges */, miscFileMaxWriteParallel), nil

	case checkpointfiles.FSCheckpointManifestFileName:
		if !s.allowFSCheckpointWrites {
			log.Warningf("gcs.FileServer.OpenWrite: attempted to open %q with allowFSCheckpointWrites disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for writing", s.bucket.BucketName(), obj.ObjectName())
		return NewWriter(s.ctx, obj, manifestFileMaxWriteBytes, 1 /* maxRanges */, manifestFileMaxWriteParallel), nil

	case checkpointfiles.FSCheckpointMultiTarFileName:
		if !s.allowFSCheckpointWrites {
			log.Warningf("gcs.FileServer.OpenWrite: attempted to open %q with allowFSCheckpointWrites disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for writing", s.bucket.BucketName(), obj.ObjectName())
		return NewWriter(s.ctx, obj, miscFileMaxWriteBytes, 1 /* maxRanges */, miscFileMaxWriteParallel), nil

	case checkpointfiles.PagesMetadataFileName:
		if !s.allowCheckpointWrites && !s.allowFSCheckpointWrites {
			log.Warningf("gcs.FileServer.OpenWrite: attempted to open %q with allowCheckpointWrites and allowFSCheckpointWrites disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for writing", s.bucket.BucketName(), obj.ObjectName())
		return NewWriter(s.ctx, obj, miscFileMaxWriteBytes, 1 /* maxRanges */, miscFileMaxWriteParallel), nil

	case checkpointfiles.PagesFileName:
		if !s.allowCheckpointWrites && !s.allowFSCheckpointWrites {
			log.Warningf("gcs.FileServer.OpenWrite: attempted to open %q with allowCheckpointWrites and allowFSCheckpointWrites disabled", path)
			return nil, fs.ErrPermission
		}
		obj := s.bucket.Object(s.objectPrefix + path)
		log.Infof("Opening gs://%s/%s for writing", s.bucket.BucketName(), obj.ObjectName())
		// Provision one range per page, which is the most that
		// pgalloc.MemoryFile saving can require. Since Writer and
		// ParallelWriter don't (can't) use writev, we aren't subject to
		// UIO_MAXIOV.
		maxRanges := int(pagesFileMaxWriteBytes / uint64(os.Getpagesize()))
		if s.getParallelCompositeUploadEnabled() {
			w, err := NewParallelWriter(s.ctx, s.bucket, obj, pagesFileMaxWriteBytes, maxRanges, pagesFileMaxPCUWriteParallel)
			if err == nil {
				return w, nil
			}
			log.Warningf("NewParallelWriter failed: %v; falling back to Writer", err)
		}
		return NewWriter(s.ctx, obj, pagesFileMaxWriteBytes, maxRanges, pagesFileMaxWriteParallel), nil

	default:
		log.Warningf("gcs.FileServer.OpenWrite: unknown path %q", path)
		return nil, fs.ErrPermission
	}
}

func (s *FileServer) getParallelCompositeUploadEnabled() bool {
	s.pcuEnabledOnce.Do(func() {
		s.pcuEnabled = func() bool {
			if s.pcuMode == ParallelCompositeUploadDisable {
				log.Infof("Disabling parallel composite upload: as specified")
				return false
			}
			if s.pcuMode == ParallelCompositeUploadForce {
				log.Infof("Enabling parallel composite upload: as specified")
				return true
			}
			name := s.bucket.BucketName()
			attrs, err := s.bucket.Attrs(s.ctx)
			if err != nil {
				log.Warningf("Disabling parallel composite upload: bucket %s attributes not available: %v", name, err)
				return false
			}
			if attrs.StorageClass != "STANDARD" {
				log.Infof("Disabling parallel composite upload: bucket %s has non-standard default storage class", name)
				return false
			}
			if attrs.RetentionPolicy != nil {
				log.Infof("Disabling parallel composite upload: bucket %s has retention policy", name)
				return false
			}
			if attrs.DefaultEventBasedHold {
				log.Infof("Disabling parallel composite upload: bucket %s has default event-based holds enabled", name)
				return false
			}
			// `gcloud storage cp`'s
			// parallel_composite_upload_compatibility_check does not include
			// the following check. However, `gcloud storage cp` has all of the
			// data to be written in advance, so it only needs to perform a
			// single composition from at most 32 chunks, resulting in
			// temporary storage overhead equal to file size. We do not have
			// this property, so we may need to perform compositions
			// recursively, resulting in temporary storage overhead that is
			// superlinear in file size.
			if attrs.SoftDeletePolicy != nil && attrs.SoftDeletePolicy.RetentionDuration != 0 {
				log.Infof("Disabling parallel composite upload: bucket %s has soft deletion enabled", name)
				return false
			}
			log.Infof("Enabling parallel composite upload: bucket %s passed safety checks", name)
			return true
		}()
	})
	return s.pcuEnabled
}
