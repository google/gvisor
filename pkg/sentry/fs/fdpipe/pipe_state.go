// Copyright 2018 Google LLC
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

package fdpipe

import (
	"fmt"
	"io/ioutil"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// beforeSave is invoked by stateify.
func (p *pipeOperations) beforeSave() {
	if p.flags.Read {
		data, err := ioutil.ReadAll(p.file)
		if err != nil && !isBlockError(err) {
			panic(fmt.Sprintf("failed to read from pipe: %v", err))
		}
		p.readAheadBuffer = append(p.readAheadBuffer, data...)
	} else if p.flags.Write {
		file, err := p.opener.NonBlockingOpen(context.Background(), fs.PermMask{Write: true})
		if err != nil {
			panic(fs.ErrSaveRejection{fmt.Errorf("write-only pipe end cannot be re-opened as %v: %v", p, err)})
		}
		file.Close()
	}
}

// saveFlags is invoked by stateify.
func (p *pipeOperations) saveFlags() fs.FileFlags {
	return p.flags
}

// readPipeOperationsLoading is used to ensure that write-only pipe fds are
// opened after read/write and read-only pipe fds, to avoid ENXIO when
// multiple pipe fds refer to different ends of the same pipe.
var readPipeOperationsLoading sync.WaitGroup

// loadFlags is invoked by stateify.
func (p *pipeOperations) loadFlags(flags fs.FileFlags) {
	// This is a hack to ensure that readPipeOperationsLoading includes all
	// readable pipe fds before any asynchronous calls to
	// readPipeOperationsLoading.Wait().
	if flags.Read {
		readPipeOperationsLoading.Add(1)
	}
	p.flags = flags
}

// afterLoad is invoked by stateify.
func (p *pipeOperations) afterLoad() {
	load := func() error {
		if !p.flags.Read {
			readPipeOperationsLoading.Wait()
		} else {
			defer readPipeOperationsLoading.Done()
		}
		var err error
		p.file, err = p.opener.NonBlockingOpen(context.Background(), fs.PermMask{
			Read:  p.flags.Read,
			Write: p.flags.Write,
		})
		if err != nil {
			return fmt.Errorf("unable to open pipe %v: %v", p, err)
		}
		if err := p.init(); err != nil {
			return fmt.Errorf("unable to initialize pipe %v: %v", p, err)
		}
		return nil
	}

	// Do background opening of pipe ends. Note for write-only pipe ends we
	// have to do it asynchronously to avoid blocking the restore.
	fs.Async(fs.CatchError(load))
}
