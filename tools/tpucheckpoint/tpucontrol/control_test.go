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

package tpucontrol_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	tpupb "gvisor.dev/gvisor/pkg/sentry/control/tpu_control_proto_go_proto"
	"gvisor.dev/gvisor/tools/tpucheckpoint/tpucontrol"
)

type pipePair struct {
	threadName   string
	reqWriteFD   int
	rspReadFD    int
	reqWriteFile *os.File
	rspReadFile  *os.File
}

func setupPipeTest(t *testing.T, pid int, pipes []pipePair) {
	t.Helper()
	root := t.TempDir()
	old := tpucontrol.ProcRoot
	tpucontrol.ProcRoot = root
	t.Cleanup(func() { tpucontrol.ProcRoot = old })

	pidDir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", pidDir, err)
	}

	oldOpen := tpucontrol.OpenPipeFile
	t.Cleanup(func() { tpucontrol.OpenPipeFile = oldOpen })

	fdMap := make(map[string]*os.File)
	for i, pp := range pipes {
		tid := 1000 + i
		tidDir := filepath.Join(pidDir, "task", strconv.Itoa(tid))
		if err := os.MkdirAll(tidDir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", tidDir, err)
		}
		if err := os.WriteFile(filepath.Join(tidDir, "comm"), []byte(pp.threadName+"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile comm: %v", err)
		}

		fdMap[tpucontrol.PipePath(pid, pp.reqWriteFD)] = pp.reqWriteFile
		fdMap[tpucontrol.PipePath(pid, pp.rspReadFD)] = pp.rspReadFile
	}

	tpucontrol.OpenPipeFile = func(path string, flag int) (*os.File, error) {
		if f, ok := fdMap[path]; ok {
			return f, nil
		}
		return nil, os.ErrNotExist
	}
}

func marshalResponse(t *testing.T, success bool, state tpupb.RuntimeState, errMsg string) []byte {
	t.Helper()
	resp := tpupb.ControlResponse_builder{
		Success:      proto.Bool(success),
		CurrentState: state.Enum(),
		ErrorMessage: proto.String(errMsg),
	}.Build()
	data, err := proto.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return data
}

func writeDelimited(f *os.File, msg []byte) {
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(msg)))
	f.Write(sizeBuf[:])
	f.Write(msg)
}

// readRequest consumes one framed request message from the pipe.
func readRequest(reqRead *os.File) {
	var sizeBuf [4]byte
	if _, err := reqRead.Read(sizeBuf[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(sizeBuf[:])
	discard := make([]byte, size)
	reqRead.Read(discard)
}

func mockResponder(t *testing.T, reqRead, rspWrite *os.File, success bool, state tpupb.RuntimeState, errMsg string) {
	t.Helper()
	resp := marshalResponse(t, success, state, errMsg)
	go func() {
		defer rspWrite.Close()
		readRequest(reqRead)
		writeDelimited(rspWrite, resp)
	}()
}

func TestCheckpointSuccess(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	mockResponder(t, reqRead, rspWrite, true, tpupb.RuntimeState_STATE_DETACHED, "")

	if err := tpucontrol.Checkpoint(42, 10); err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}
}

func TestRestoreSuccess(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	mockResponder(t, reqRead, rspWrite, true, tpupb.RuntimeState_STATE_RUNNING, "")

	if err := tpucontrol.Restore(42, 10); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
}

func TestGetStateSuccess(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	mockResponder(t, reqRead, rspWrite, true, tpupb.RuntimeState_STATE_DETACHED, "")

	state, err := tpucontrol.GetState(42, 10)
	if err != nil {
		t.Fatalf("GetState() error = %v", err)
	}
	if state != tpupb.RuntimeState_STATE_DETACHED {
		t.Errorf("GetState() = %v, want %v", state, tpupb.RuntimeState_STATE_DETACHED)
	}
}

func TestControlFailureResponse(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	mockResponder(t, reqRead, rspWrite, false, tpupb.RuntimeState_STATE_FAULTED, "device busy")

	err := tpucontrol.Checkpoint(42, 10)
	if err == nil {
		t.Fatal("expected error for failure response")
	}

	var cfe *tpucontrol.ControlFailedError
	if !errors.As(err, &cfe) {
		t.Fatalf("expected ControlFailedError, got %T: %v", err, err)
	}
	if cfe.ErrorMessage != "device busy" {
		t.Errorf("ErrorMessage = %q, want %q", cfe.ErrorMessage, "device busy")
	}
	if cfe.CurrentState != tpupb.RuntimeState_STATE_FAULTED {
		t.Errorf("CurrentState = %v, want %v", cfe.CurrentState, tpupb.RuntimeState_STATE_FAULTED)
	}
}

func TestControlTimeout(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()
	defer rspWrite.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	// Read the request but never write a response.
	go func() {
		readRequest(reqRead)
		time.Sleep(5 * time.Second)
	}()

	err := tpucontrol.Checkpoint(42, 1)
	if err == nil {
		t.Fatal("expected timeout error")
	}

	var te *tpucontrol.TimeoutError
	if !errors.As(err, &te) {
		// Pipe deadlines may surface as a ProtocolError on some kernels.
		var pe *tpucontrol.ProtocolError
		if !errors.As(err, &pe) {
			t.Fatalf("expected TimeoutError or ProtocolError, got %T: %v", err, err)
		}
	}
}

func TestControlPipeClosed(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	// Read the request, then close the response pipe without writing.
	go func() {
		readRequest(reqRead)
		rspWrite.Close()
	}()

	err := tpucontrol.Checkpoint(42, 10)
	if err == nil {
		t.Fatal("expected error for closed pipe")
	}

	var pe *tpucontrol.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
}

func TestControlCorruptedResponse(t *testing.T) {
	reqRead, reqWrite, _ := os.Pipe()
	rspRead, rspWrite, _ := os.Pipe()
	defer reqRead.Close()

	setupPipeTest(t, 42, []pipePair{{
		threadName:   "libtpu00010002",
		reqWriteFD:   1,
		rspReadFD:    2,
		reqWriteFile: reqWrite,
		rspReadFile:  rspRead,
	}})

	go func() {
		defer rspWrite.Close()
		readRequest(reqRead)

		// Valid size prefix but a truncated varint payload.
		writeDelimited(rspWrite, []byte{0x08})
	}()

	err := tpucontrol.Checkpoint(42, 10)
	if err == nil {
		t.Fatal("expected error for corrupted response")
	}

	var pe *tpucontrol.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected ProtocolError, got %T: %v", err, err)
	}
}

func TestControlAllMultipleThreads(t *testing.T) {
	reqRead1, reqWrite1, _ := os.Pipe()
	rspRead1, rspWrite1, _ := os.Pipe()
	reqRead2, reqWrite2, _ := os.Pipe()
	rspRead2, rspWrite2, _ := os.Pipe()
	defer reqRead1.Close()
	defer reqRead2.Close()

	setupPipeTest(t, 42, []pipePair{
		{threadName: "libtpu00010002", reqWriteFD: 1, rspReadFD: 2, reqWriteFile: reqWrite1, rspReadFile: rspRead1},
		{threadName: "libtpu00030004", reqWriteFD: 3, rspReadFD: 4, reqWriteFile: reqWrite2, rspReadFile: rspRead2},
	})

	mockResponder(t, reqRead1, rspWrite1, true, tpupb.RuntimeState_STATE_DETACHED, "")
	mockResponder(t, reqRead2, rspWrite2, true, tpupb.RuntimeState_STATE_DETACHED, "")

	if err := tpucontrol.Checkpoint(42, 10); err != nil {
		t.Fatalf("Checkpoint() error = %v", err)
	}
}

func TestControlAllFirstFails(t *testing.T) {
	reqRead1, reqWrite1, _ := os.Pipe()
	rspRead1, rspWrite1, _ := os.Pipe()
	reqRead2, reqWrite2, _ := os.Pipe()
	rspRead2, rspWrite2, _ := os.Pipe()
	defer reqRead1.Close()
	defer reqRead2.Close()
	defer rspWrite2.Close()

	setupPipeTest(t, 42, []pipePair{
		{threadName: "libtpu00010002", reqWriteFD: 1, rspReadFD: 2, reqWriteFile: reqWrite1, rspReadFile: rspRead1},
		{threadName: "libtpu00030004", reqWriteFD: 3, rspReadFD: 4, reqWriteFile: reqWrite2, rspReadFile: rspRead2},
	})

	// The first thread fails; the operation should report the failure.
	mockResponder(t, reqRead1, rspWrite1, false, tpupb.RuntimeState_STATE_FAULTED, "device error")

	err := tpucontrol.Checkpoint(42, 10)
	if err == nil {
		t.Fatal("expected error when first thread fails")
	}

	var cfe *tpucontrol.ControlFailedError
	if !errors.As(err, &cfe) {
		t.Fatalf("expected ControlFailedError, got %T: %v", err, err)
	}
}

func TestCheckProcessExists(t *testing.T) {
	root := t.TempDir()
	old := tpucontrol.ProcRoot
	tpucontrol.ProcRoot = root
	defer func() { tpucontrol.ProcRoot = old }()

	// PID doesn't exist.
	err := tpucontrol.CheckProcessExists(12345)
	if err == nil {
		t.Error("expected error for non-existent PID")
	}
	var de *tpucontrol.DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("expected DiscoveryError, got %T", err)
	}

	// Create the PID dir.
	if err := os.MkdirAll(filepath.Join(root, "12345"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := tpucontrol.CheckProcessExists(12345); err != nil {
		t.Errorf("unexpected error for existing PID: %v", err)
	}
}
