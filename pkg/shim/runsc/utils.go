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

package runsc

import (
	"bytes"
	"strings"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
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

// FormatRunscLogPath parses runsc config, and fill in %ID% in the log path.
func FormatRunscLogPath(id string, config map[string]string) {
	if path, ok := config["debug-log"]; ok {
		config["debug-log"] = strings.Replace(path, "%ID%", id, -1)
	}
}

// FormatShimLogPath creates the file path to the log file. It replaces %ID%
// in the path with the provided "id". It also uses a default log name if the
// path end with '/'.
func FormatShimLogPath(path string, id string) string {
	if strings.HasSuffix(path, "/") {
		// Default format: <path>/runsc-shim-<ID>.log
		path += "runsc-shim-%ID%.log"
	}
	return strings.Replace(path, "%ID%", id, -1)
}
