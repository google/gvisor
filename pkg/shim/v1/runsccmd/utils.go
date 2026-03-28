// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsccmd

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

func getBuf() *bytes.Buffer {
	return bytesBufferPool.Get().(*bytes.Buffer)
}

func putBuf(b *bytes.Buffer) {
	b.Reset()
	bytesBufferPool.Put(b)
}

// FormatShimLogPath creates the file path to the log file. It replaces %ID%
// in the path with the provided "id". It also uses a default log name if the
// path ends with '/'.
func FormatShimLogPath(path string, id string) string {
	if strings.HasSuffix(path, "/") {
		// Default format: <path>/runsc-shim-<ID>.log
		path += fmt.Sprintf("runsc-shim-%s.log", id)
	}
	return path
}
