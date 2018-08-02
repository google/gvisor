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

package proc

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
)

// filesystemsData backs /proc/filesystems.
//
// +stateify savable
type filesystemsData struct{}

// NeedsUpdate returns true on the first generation. The set of registered file
// systems doesn't change so there's no need to generate SeqData more than once.
func (*filesystemsData) NeedsUpdate(generation int64) bool {
	return generation == 0
}

// ReadSeqFileData returns data for the SeqFile reader.
// SeqData, the current generation and where in the file the handle corresponds to.
func (*filesystemsData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	// We don't ever expect to see a non-nil SeqHandle.
	if h != nil {
		return nil, 0
	}

	// Generate the file contents.
	var buf bytes.Buffer
	for _, sys := range fs.GetFilesystems() {
		if !sys.AllowUserList() {
			continue
		}
		nodev := "nodev"
		if sys.Flags()&fs.FilesystemRequiresDev != 0 {
			nodev = ""
		}
		// Matches the format of fs/filesystems.c:filesystems_proc_show.
		fmt.Fprintf(&buf, "%s\t%s\n", nodev, sys.Name())
	}

	// Return the SeqData and advance the generation counter.
	return []seqfile.SeqData{{Buf: buf.Bytes(), Handle: (*filesystemsData)(nil)}}, 1
}
