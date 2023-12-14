// Copyright 2023 The gVisor Authors.
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

package boot

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/runsc/boot/pprof"
)

type restorer struct {
	container  *containerInfo
	stateFile  *os.File
	deviceFile *os.File
}

func (r *restorer) restore(l *Loader) error {
	// Save the current network stack to slap on top of the one that was restored.
	curNetwork := l.k.RootNetworkNamespace().Stack()
	if eps, ok := curNetwork.(*netstack.Stack); ok {
		stack.StackFromEnv = eps.Stack // FIXME(b/36201077)
	}

	p, err := createPlatform(l.root.conf, r.deviceFile)
	if err != nil {
		return fmt.Errorf("creating platform: %v", err)
	}
	// Replace the old kernel with a new one that will be restored into.
	l.k = &kernel.Kernel{
		Platform: p,
	}

	mf, err := createMemoryFile()
	if err != nil {
		return fmt.Errorf("creating memory file: %v", err)
	}
	l.k.SetMemoryFile(mf)

	if l.root.conf.ProfileEnable {
		// pprof.Initialize opens /proc/self/maps, so has to be called before
		// installing seccomp filters.
		pprof.Initialize()
	}

	// Seccomp filters have to be applied before vfs restore and before parsing
	// the state file.
	if err := l.installSeccompFilters(); err != nil {
		return err
	}

	// Set up the restore environment.
	ctx := l.k.SupervisorContext()
	// TODO(b/298078576): Need to process hints here probably
	mntr := newContainerMounter(&l.root, l.k, l.mountHints, l.sharedMounts, l.productName, l.sandboxID, l.cgroupMounts)
	ctx, err = mntr.configureRestore(ctx)
	if err != nil {
		return fmt.Errorf("configuring filesystem restore: %v", err)
	}

	// Load the state.
	loadOpts := state.LoadOpts{Source: r.stateFile}
	if err := loadOpts.Load(ctx, l.k, nil, curNetwork, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}); err != nil {
		return err
	}

	// Since we have a new kernel we also must make a new watchdog.
	dogOpts := watchdog.DefaultOpts
	dogOpts.TaskTimeoutAction = l.root.conf.WatchdogAction
	dog := watchdog.New(l.k, dogOpts)

	// Change the loader fields to reflect the changes made when restoring.
	l.watchdog = dog
	l.root.procArgs = kernel.CreateProcessArgs{}
	l.restore = true

	// Reinitialize the sandbox ID and processes map. Note that it doesn't
	// restore the state of multiple containers, nor exec processes.
	l.sandboxID = r.container.cid

	l.mu.Lock()
	defer l.mu.Unlock()

	// Set new container ID if it has changed.
	tasks := l.k.TaskSet().Root.Tasks()
	if tasks[0].ContainerID() != l.sandboxID { // There must be at least 1 task.
		for _, task := range tasks {
			task.RestoreContainerID(l.sandboxID)
		}
	}

	eid := execID{cid: l.sandboxID}
	l.processes = map[execID]*execProcess{
		eid: {
			tg: l.k.GlobalInit(),
		},
	}

	return nil
}
