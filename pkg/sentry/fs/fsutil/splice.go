// Copyright 2018 Google LLC
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

package fsutil

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// FDProvider may operationally be implemented by FileOperations, and it used
// by some underlying implementations to implement e.g. splice operations.
type FDProvider interface {
	// FD returns a host file descriptor.
	//
	// If < 0, then no FD is available. All callers of the FD function must
	// check for this condition and behave accordingly.
	FD() int
}

// WriteTo performs a host-native WriteTo operation for splicing.
//
// This implements checks whether the relevant FileOperations support the
// FDProvider interface in order to extract FDs.
func WriteTo(ctx context.Context, src *fs.File, dst *fs.File, opts fs.SpliceOpts) (int64, error) {
	// Extract the source file descriptor.
	srcFDP, ok := src.FileOperations.(FDProvider)
	if !ok {
		return 0, syserror.ENOSYS // Not possible.
	}
	srcFD := srcFDP.FD()
	if srcFD < 0 {
		return 0, syserror.ENOSYS // Not available.
	}

	// Extract the destination file descriptor.
	dstFDP, ok := dst.FileOperations.(FDProvider)
	if !ok {
		return 0, syserror.ENOSYS // Not possible.
	}
	dstFD := dstFDP.FD()
	if dstFD < 0 {
		return 0, syserror.ENOSYS // Not available.
	}

	// We must manually execute this seek to ensure that data lands in the
	// right spot. Note that the file should already be protected by the
	// appropriate lock. This will fail if it's not possible to use a
	// specific offset (i.e. the file is a pipe or a socket).
	if opts.DstOffset {
		if _, err := syscall.Seek(dstFD, opts.DstStart, 0); err != nil {
			return 0, err
		}
	}

	// We can only handle Dup with pipes. This is because the tee system
	// call is supported only for pipes; and we can't safely emulate this
	// operation here.
	if opts.Dup {
		// Just attempt the tee. If the file is a pipe, then this will
		// work. If it isn't then the tee will return EINVAL, which is
		// what we want anyways.
		return tee(srcFD, dstFD, opts.Length)
	}

	// Otherwise, we can generally use sendfile to ship references between
	// two file descriptors.
	if !opts.SrcOffset {
		// The object must be a pipe or something with a native offset;
		// we just call sendfile with a null offset.
		return sendfile(dstFD, srcFD, nil, opts.Length)
	}

	return sendfile(dstFD, srcFD, &opts.SrcStart, opts.Length)
}
