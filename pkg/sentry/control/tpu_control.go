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

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	tpu_pb "gvisor.dev/gvisor/pkg/sentry/control/tpu_control_proto_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/vfio"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tpuTasksStateKey      = "tpu-tasks"
	tpuThreadNamePrefix   = "libtpu"
	libtpuResponseTimeout = 3 * time.Minute
)

type tpuTaskInfo struct {
	task       *kernel.Task
	reqWriteFd int32
	rspReadFd  int32
}

func preSaveTPU(k *kernel.Kernel) error {
	tpuTasks := findTPUTasks(k)
	if len(tpuTasks) == 0 {
		return nil
	}

	var tasks []*kernel.Task
	for _, info := range tpuTasks {
		tasks = append(tasks, info.task)
	}
	k.AddStateToCheckpoint(tpuTasksStateKey, tasks)

	if err := controlTPUTasks(k, tpu_pb.ControlAction_ACTION_CHECKPOINT, tpuTasks); err != nil {
		return fmt.Errorf("TPU checkpoint failed: %w", err)
	}
	return nil
}

func postRestoreTPU(k *kernel.Kernel) error {
	return postResumeTPU(k)
}

func postResumeTPU(k *kernel.Kernel) error {
	tpuTasksVal := k.PopCheckpointState(tpuTasksStateKey)
	var tpuTasks []*tpuTaskInfo
	if tpuTasksVal != nil {
		tasks := tpuTasksVal.([]*kernel.Task)
		for _, t := range tasks {
			info, err := extractTPUTaskInfo(t)
			if err != nil {
				log.Warningf("Failed to extract TPU task info for task %d: %v", t.ThreadID(), err)
				continue
			}
			tpuTasks = append(tpuTasks, info)
		}
	} else {
		tpuTasks = findTPUTasks(k)
	}

	if len(tpuTasks) == 0 {
		return nil
	}

	if err := controlTPUTasks(k, tpu_pb.ControlAction_ACTION_RESTORE, tpuTasks); err != nil {
		return fmt.Errorf("TPU restore failed: %w", err)
	}
	return nil
}

func findTPUTasks(k *kernel.Kernel) []*tpuTaskInfo {
	var infos []*tpuTaskInfo
	sctx := k.SupervisorContext()
	k.TaskSet().ForEachThreadGroup(func(tg *kernel.ThreadGroup, tgLeader *kernel.Task) {
		hasTPU := false
		tgLeader.WithMuLocked(func(t *kernel.Task) {
			t.FDTable().ForEach(sctx, func(_ int32, file *vfs.FileDescription, _ kernel.FDFlags) bool {
				if isTPUDevice(file) {
					hasTPU = true
					return false
				}
				return true
			})
		})

		if !hasTPU {
			return
		}

		tg.ForEachTask(func(t *kernel.Task) bool {
			tpuInfo, err := extractTPUTaskInfo(t)
			if err != nil {
				log.Warningf("Failed to extract TPU task info for task %d: %v", t.ThreadID(), err)
				return true
			}
			infos = append(infos, tpuInfo)
			return true
		})
	})
	return infos
}

func controlTPUTasks(k *kernel.Kernel, action tpu_pb.ControlAction, tpuTasks []*tpuTaskInfo) error {
	sctx := k.SupervisorContext()
	if len(tpuTasks) == 0 {
		return nil
	}

	log.Infof("Found %d TPU tasks, sending action %v", len(tpuTasks), action)

	var wg sync.WaitGroup
	var errs []error
	var errsMu sync.Mutex

	for _, info := range tpuTasks {
		t := info.task
		fdTable := t.FDTable()
		if fdTable == nil {
			return fmt.Errorf("task %d has no FD table", t.ThreadID())
		}

		reqFile, _ := fdTable.Get(info.reqWriteFd)
		if reqFile == nil {
			return fmt.Errorf("failed to get reqWriteFd %d for task %d", info.reqWriteFd, t.ThreadID())
		}

		rspFile, _ := fdTable.Get(info.rspReadFd)
		if rspFile == nil {
			reqFile.DecRef(sctx)
			return fmt.Errorf("failed to get rspReadFd %d for task %d", info.rspReadFd, t.ThreadID())
		}

		wg.Add(1)
		go func(info *tpuTaskInfo, reqFile, rspFile *vfs.FileDescription) {
			defer wg.Done()
			defer reqFile.DecRef(sctx)
			defer rspFile.DecRef(sctx)

			if err := controlTPUTask(sctx, info, action, reqFile, rspFile); err != nil {
				errsMu.Lock()
				errs = append(errs, err)
				errsMu.Unlock()
			}
		}(info, reqFile, rspFile)
	}

	wg.Wait()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func controlTPUTask(sctx context.Context, info *tpuTaskInfo, action tpu_pb.ControlAction, reqFile, rspFile *vfs.FileDescription) error {
	t := info.task

	req := tpu_pb.ControlRequest_builder{
		Action:      action.Enum(),
		TimeoutSecs: proto.Int32(int32(libtpuResponseTimeout.Seconds())),
	}.Build()

	log.Debugf("Writing request %v to FD %d of task %d", req, info.reqWriteFd, t.ThreadID())
	if err := writeDelimitedProto(sctx, reqFile, req); err != nil {
		return fmt.Errorf("failed to write request to reqWriteFd %d for task %d: %w", info.reqWriteFd, t.ThreadID(), err)
	}

	log.Debugf("Waiting for response on FD %d of task %d", info.rspReadFd, t.ThreadID())
	resp := &tpu_pb.ControlResponse{}
	if err := readDelimitedProto(sctx, rspFile, resp, libtpuResponseTimeout); err != nil {
		return fmt.Errorf("failed to read response from rspReadFd %d for task %d: %w", info.rspReadFd, t.ThreadID(), err)
	}

	log.Infof("TPU task %d responded: %v", t.ThreadID(), resp)
	if !resp.GetSuccess() {
		return fmt.Errorf("TPU task %d failed: %s", t.ThreadID(), resp.GetErrorMessage())
	}
	return nil
}

func writeDelimitedProto(sctx context.Context, file *vfs.FileDescription, msg proto.Message) error {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	size := uint32(len(bytes))
	buf := make([]byte, 4+size)
	binary.BigEndian.PutUint32(buf[:4], size)
	copy(buf[4:], bytes)

	n, err := file.Write(sctx, usermem.BytesIOSequence(buf), vfs.WriteOptions{})
	if err != nil {
		return err
	}
	if n != int64(len(buf)) {
		return fmt.Errorf("partial write: wrote %d bytes, expected %d", n, len(buf))
	}
	return nil
}

func readExactly(sctx context.Context, file *vfs.FileDescription, buf []byte, timeout time.Duration) error {
	var (
		readNotifyCh  chan struct{}
		readWaitEntry waiter.Entry
	)
	defer func() {
		if readNotifyCh != nil {
			file.EventUnregister(&readWaitEntry)
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	readBytes := 0
	for readBytes < len(buf) {
		rn, err := file.Read(sctx, usermem.BytesIOSequence(buf[readBytes:]), vfs.ReadOptions{})
		if linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			if readNotifyCh == nil {
				readWaitEntry, readNotifyCh = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr)
				file.EventRegister(&readWaitEntry)
			}
			select {
			case <-readNotifyCh:
				continue
			case <-timer.C:
				return fmt.Errorf("timeout waiting for read (timeout %v)", timeout)
			}
		}
		if err != nil {
			return err
		}
		if rn == 0 {
			return io.EOF
		}
		readBytes += int(rn)
	}
	return nil
}

func readDelimitedProto(sctx context.Context, file *vfs.FileDescription, msg proto.Message, timeout time.Duration) error {
	sizeBuf := make([]byte, 4)
	if err := readExactly(sctx, file, sizeBuf, timeout); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(sizeBuf)
	if size > 1024*1024 { // Sanity check: 1MB limit
		return fmt.Errorf("proto size too large: %d", size)
	}
	protoBuf := make([]byte, size)
	if err := readExactly(sctx, file, protoBuf, timeout); err != nil {
		return err
	}
	return proto.Unmarshal(protoBuf, msg)
}

func isTPUDevice(file *vfs.FileDescription) bool {
	impl := file.Impl()
	if impl == nil {
		return false
	}
	return vfio.IsVFIOFD(impl)
}

func extractTPUTaskInfo(t *kernel.Task) (*tpuTaskInfo, error) {
	name := t.Name()
	if !strings.HasPrefix(name, tpuThreadNamePrefix) {
		return nil, fmt.Errorf("task %d does not have a TPU thread name", t.ThreadID())
	}
	hexFd := strings.TrimPrefix(name, tpuThreadNamePrefix)
	if len(hexFd) != 8 {
		return nil, fmt.Errorf("invalid TPU thread name format %s", name)
	}
	reqWriteFd, err := strconv.ParseInt(hexFd[:4], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reqWriteFd %s: %v", hexFd[:4], err)
	}
	rspReadFd, err := strconv.ParseInt(hexFd[4:], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rspReadFd %s: %v", hexFd[4:], err)
	}
	return &tpuTaskInfo{
		task:       t,
		reqWriteFd: int32(reqWriteFd),
		rspReadFd:  int32(rspReadFd),
	}, nil
}
