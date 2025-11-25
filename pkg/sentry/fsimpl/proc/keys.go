// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (fs *filesystem) newMaxKeySizeFile(ctx context.Context, k *kernel.Kernel, creds *auth.Credentials) kernfs.Inode {
	s := &maxKeySize{maxKeys: &k.MaxKeySetSize}
	s.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), s, 0644)
	return s
}

// maxKeySize implements vfs.WritableDynamicBytesSource for
// /proc/sys/kernel/keys/maxkeys.
//
// +stateify savable
type maxKeySize struct {
	kernfs.DynamicBytesFile

	// maxKeys is the maximum number of keys allowed in a key set.
	maxKeys *atomicbitops.Int32
}

var _ vfs.WritableDynamicBytesSource = (*maxKeySize)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *maxKeySize) Generate(ctx context.Context, buf *bytes.Buffer) error {
	_, err := fmt.Fprintf(buf, "%d\n", s.maxKeys.Load())
	return err
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (s *maxKeySize) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// Ignore partial writes.
		return 0, linuxerr.EINVAL
	}
	if !auth.CredentialsFromContext(ctx).HasCapability(linux.CAP_SYS_ADMIN) {
		return 0, linuxerr.EPERM
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}

	if buf[0] <= 0 {
		return 0, linuxerr.EINVAL
	}

	s.maxKeys.Store(buf[0])
	return n, nil
}
