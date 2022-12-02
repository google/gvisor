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

package iouringfs

// beforeSave is invoked by stateify.
func (fd *FileDescription) beforeSave() {
	if fd.running.Load() != 0 {
		panic("Task goroutine in fd.ProcessSubmissions during Save! This shouldn't be possible due to Kernel.Pause")
	}
}

// afterLoad is invoked by stateify.
func (fd *FileDescription) afterLoad() {
	fd.runC = make(chan struct{}, 1)
	// Wake up any potential sleepers from before the Save. The Pause for Save
	// ensured there were no active tasks at save time.
	fd.runC <- struct{}{}
}
