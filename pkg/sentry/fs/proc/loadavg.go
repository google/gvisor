// Copyright 2018 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
)

// loadavgData backs /proc/loadavg.
//
// +stateify savable
type loadavgData struct{}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*loadavgData) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (d *loadavgData) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	var buf bytes.Buffer

	// TODO(b/62345059): Include real data in fields.
	// Column 1-3: CPU and IO utilization of the last 1, 5, and 10 minute periods.
	// Column 4-5: currently running processes and the total number of processes.
	// Column 6: the last process ID used.
	fmt.Fprintf(&buf, "%.2f %.2f %.2f %d/%d %d\n", 0.00, 0.00, 0.00, 0, 0, 0)

	return []seqfile.SeqData{
		{
			Buf:    buf.Bytes(),
			Handle: (*loadavgData)(nil),
		},
	}, 0
}
