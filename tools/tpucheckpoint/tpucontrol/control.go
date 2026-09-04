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

package tpucontrol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	tpupb "gvisor.dev/gvisor/pkg/sentry/control/tpu_control_proto_go_proto"
)

const (
	defaultTimeoutSecs = 180

	// maxResponseBytes bounds the response message size read from the
	// pipe, as a defense against a corrupted size prefix.
	maxResponseBytes = 1 << 20
)

// OpenPipeFile opens a pipe by path. Overridable for tests to supply
// pre-opened pipes.
var OpenPipeFile = func(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0)
}

// Result holds the outcome of an operation on a single PID.
type Result struct {
	PID      int
	Err      error
	Duration time.Duration

	// State is only set by GetState.
	State tpupb.RuntimeState
}

// ParsePIDs parses a comma-separated list of PIDs.
func ParsePIDs(arg string) ([]int, error) {
	var pids []int
	for _, s := range strings.Split(arg, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		pid, err := strconv.Atoi(s)
		if err != nil || pid <= 0 {
			return nil, fmt.Errorf("invalid PID: %q", s)
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no PIDs specified")
	}
	return pids, nil
}

// CheckProcessExists verifies that the target process is alive.
func CheckProcessExists(pid int) error {
	path := fmt.Sprintf("%s/%d", ProcRoot, pid)
	if _, err := os.Stat(path); err != nil {
		return &DiscoveryError{PID: pid, Err: fmt.Errorf("process not found: %w", err)}
	}
	return nil
}

// Checkpoint sends ACTION_CHECKPOINT to all libtpu threads of every PID,
// concurrently across PIDs. Results are indexed to match pids.
func Checkpoint(pids []int, timeoutSecs int) []Result {
	return forEachPID(pids, func(r *Result) {
		r.Err = controlPid(r.PID, tpupb.ControlAction_ACTION_CHECKPOINT, timeoutSecs)
	})
}

// Restore sends ACTION_RESTORE to all libtpu threads of every PID,
// concurrently across PIDs. Results are indexed to match pids.
func Restore(pids []int, timeoutSecs int) []Result {
	return forEachPID(pids, func(r *Result) {
		r.Err = controlPid(r.PID, tpupb.ControlAction_ACTION_RESTORE, timeoutSecs)
	})
}

// GetState sends ACTION_GETSTATE to the first libtpu thread of every PID,
// concurrently across PIDs. Results are indexed to match pids.
func GetState(pids []int, timeoutSecs int) []Result {
	return forEachPID(pids, func(r *Result) {
		r.State, r.Err = getStatePid(r.PID, timeoutSecs)
	})
}

// forEachPID runs op concurrently for every PID and returns the per-PID
// results, indexed to match pids.
func forEachPID(pids []int, op func(r *Result)) []Result {
	results := make([]Result, len(pids))

	var wg sync.WaitGroup
	for i, pid := range pids {
		results[i].PID = pid
		wg.Add(1)
		go func(r *Result) {
			defer wg.Done()
			start := time.Now()
			op(r)
			r.Duration = time.Since(start)
		}(&results[i])
	}
	wg.Wait()

	return results
}

func getStatePid(pid int, timeoutSecs int) (tpupb.RuntimeState, error) {
	if err := CheckProcessExists(pid); err != nil {
		return tpupb.RuntimeState_STATE_UNSPECIFIED, err
	}
	pipes, err := DiscoverPipes(pid)
	if err != nil {
		return tpupb.RuntimeState_STATE_UNSPECIFIED, &DiscoveryError{PID: pid, Err: err}
	}
	resp, err := controlOne(pid, pipes[0], tpupb.ControlAction_ACTION_GETSTATE, timeoutSecs)
	if err != nil {
		return tpupb.RuntimeState_STATE_UNSPECIFIED, err
	}
	return resp.GetCurrentState(), nil
}

func controlPid(pid int, action tpupb.ControlAction, timeoutSecs int) error {
	if err := CheckProcessExists(pid); err != nil {
		return err
	}

	pipes, err := DiscoverPipes(pid)
	if err != nil {
		return &DiscoveryError{PID: pid, Err: err}
	}

	if timeoutSecs <= 0 {
		timeoutSecs = defaultTimeoutSecs
	}

	for _, p := range pipes {
		if _, err := controlOne(pid, p, action, timeoutSecs); err != nil {
			return err
		}
	}
	return nil
}

func controlOne(pid int, pipe PipeInfo, action tpupb.ControlAction, timeoutSecs int) (*tpupb.ControlResponse, error) {
	reqPath := PipePath(pid, pipe.ReqWriteFD)
	rspPath := PipePath(pid, pipe.RspReadFD)

	reqFile, err := OpenPipeFile(reqPath, os.O_WRONLY)
	if err != nil {
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("open request pipe %s: %w", reqPath, err)}
	}
	defer reqFile.Close()

	rspFile, err := OpenPipeFile(rspPath, os.O_RDONLY)
	if err != nil {
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("open response pipe %s: %w", rspPath, err)}
	}
	defer rspFile.Close()

	if timeoutSecs > 0 {
		// SetReadDeadline may be unsupported for this FD type; in that
		// case proceed without a deadline.
		_ = rspFile.SetReadDeadline(time.Now().Add(time.Duration(timeoutSecs) * time.Second))
	}

	req := tpupb.ControlRequest_builder{
		Action:      action.Enum(),
		TimeoutSecs: proto.Int32(int32(timeoutSecs)),
	}.Build()
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("marshal request: %w", err)}
	}

	if err := writeDelimited(reqFile, reqBytes); err != nil {
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("write request: %w", err)}
	}

	respData, err := readDelimited(rspFile)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, &TimeoutError{Action: action, TID: pipe.TID, Err: err}
		}
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("read response: %w", err)}
	}

	resp := &tpupb.ControlResponse{}
	if err := proto.Unmarshal(respData, resp); err != nil {
		return nil, &ProtocolError{Action: action, TID: pipe.TID, Err: fmt.Errorf("unmarshal response: %w", err)}
	}

	if !resp.GetSuccess() {
		return nil, &ControlFailedError{
			Action:       action,
			TID:          pipe.TID,
			CurrentState: resp.GetCurrentState(),
			ErrorMessage: resp.GetErrorMessage(),
		}
	}

	return resp, nil
}

// writeDelimited writes a protobuf message framed with a 4-byte big-endian
// size prefix.
func writeDelimited(w io.Writer, msg []byte) error {
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(msg)))
	if _, err := w.Write(sizeBuf[:]); err != nil {
		return fmt.Errorf("write size prefix: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

// readDelimited reads a protobuf message framed with a 4-byte big-endian
// size prefix.
func readDelimited(r io.Reader) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, fmt.Errorf("read size prefix: %w", err)
	}
	size := binary.BigEndian.Uint32(sizeBuf[:])
	if size > maxResponseBytes {
		return nil, fmt.Errorf("message too large: %d bytes", size)
	}
	msg := make([]byte, size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("read message body (%d bytes): %w", size, err)
	}
	return msg, nil
}
