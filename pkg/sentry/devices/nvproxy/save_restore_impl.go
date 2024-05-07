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

//go:build !false
// +build !false

package nvproxy

import (
	goContext "context"
)

func (nvp *nvproxy) beforeSaveImpl() {
	nvp.objsLock()
	defer nvp.objsUnlock()
	if len(nvp.clients) != 0 {
		panic("can't save with live nvproxy clients")
	}
}

func (nvp *nvproxy) afterLoadImpl(goContext.Context) {
	// no-op
}

func (fd *frontendFD) beforeSaveImpl() {
	panic("nvproxy.frontendFD is not saveable")
}

func (fd *frontendFD) afterLoadImpl(goContext.Context) {
	panic("nvproxy.frontendFD is not restorable")
}

func (fd *uvmFD) beforeSaveImpl() {
	panic("nvproxy.uvmFD is not saveable")
}

func (fd *uvmFD) afterLoadImpl(goContext.Context) {
	panic("nvproxy.uvmFD is not restorable")
}
