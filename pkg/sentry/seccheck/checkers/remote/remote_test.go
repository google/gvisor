// Copyright 2022 The gVisor Authors.
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

package remote

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func setupServerProcess(t testing.TB) (string, func(), error) {
	exe, err := testutil.FindFile("examples/seccheck/server_cc")
	if err != nil {
		return "", nil, fmt.Errorf("error finding server_cc: %v", err)
	}

	dir, err := os.MkdirTemp(t.TempDir(), "remote")
	if err != nil {
		return "", nil, fmt.Errorf("Setup(%q): %v", dir, err)
	}
	path := filepath.Join(dir, "remote.sock")

	server := exec.Command(exe, "-q", path)
	var b bytes.Buffer
	server.Stdout = &b
	server.Stderr = &b
	if err := server.Start(); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("error running %q: %v", exe, err)
	}
	cu := cleanup.Make(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		t.Logf("Server log:\n%s", string(b.Bytes()))
		os.RemoveAll(dir)
	})
	defer cu.Clean()

	if err := testutil.Poll(func() error {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return err
			}
			return &backoff.PermanentError{Err: err}
		}
		return nil
	}, 5*time.Second); err != nil {
		t.Fatalf("error waiting for server file %q: %v", path, err)
	}
	return path, cu.Release(), nil
}

func pointRead(_ context.Context, _ seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	return &pb.Read{
		Common: common,
		Fd:     int64(info.Args[0].Int()),
		Count:  uint64(info.Args[2].SizeT()),
	}
}

func BenchmarkSmall(t *testing.B) {
	path, cleanup, err := setupServerProcess(t)
	if err != nil {
		t.Fatalf("SetupServerProcess(): %v", err)
	}
	defer cleanup()

	endpoint, err := setup(path)
	if err != nil {
		t.Fatalf("Setup(%q): %v", path, err)
	}
	endpointFD, err := fd.NewFromFile(endpoint)
	if err != nil {
		_ = endpoint.Close()
		t.Fatalf("NewFromFile(): %v", err)
	}
	_ = endpoint.Close()

	r := &Remote{endpoint: endpointFD}

	t.ResetTimer()
	t.RunParallel(func(sub *testing.PB) {
		for sub.Next() {
			info := seccheck.SyscallInfo{
				Enter: true,
				Sysno: 0,
			}
			info.Args[0].Value = 123
			info.Args[2].Value = 456
			err := r.Syscall(nil, seccheck.FieldSet{}, pointRead, nil, info)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
		}
	})
}
