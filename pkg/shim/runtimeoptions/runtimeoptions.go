// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package runtimeoptions contains the runtimeoptions proto.
package runtimeoptions

import proto "github.com/gogo/protobuf/proto"

func init() {
	// TODO(gvisor.dev/issue/6449): Upgrade runtimeoptions.proto after upgrading to containerd 1.5
	proto.RegisterType((*Options)(nil), "runtimeoptions.v1.Options")
}
