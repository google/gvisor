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

package epoll

import (
	"gvisor.googlesource.com/gvisor/pkg/ilist"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// afterLoad is invoked by stateify.
func (p *pollEntry) afterLoad() {
	p.waiter = waiter.Entry{Callback: &readyCallback{}}
	p.waiter.Context = p
	p.file = refs.NewWeakRef(p.id.File, p)
	p.id.File.EventRegister(&p.waiter, p.mask)
}

// afterLoad is invoked by stateify.
func (e *EventPoll) afterLoad() {
	e.listsMu.Lock()
	defer e.listsMu.Unlock()

	for _, ls := range []*ilist.List{&e.waitingList, &e.readyList, &e.disabledList} {
		for it := ls.Front(); it != nil; it = it.Next() {
			it.(*pollEntry).curList = ls
		}
	}

	for it := e.waitingList.Front(); it != nil; it = it.Next() {
		p := it.(*pollEntry)
		if p.id.File.Readiness(p.mask) != 0 {
			e.waitingList.Remove(p)
			e.readyList.PushBack(p)
			p.curList = &e.readyList
			e.Notify(waiter.EventIn)
		}
	}
}
