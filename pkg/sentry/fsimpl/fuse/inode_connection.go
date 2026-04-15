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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// call makes a FUSE request and unmarshals the response.
func (i *inode) call(ctx context.Context, opcode linux.FUSEOpcode, in marshal.Marshallable, out marshal.Marshallable) error {
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, opcode, in)
	res, err := i.fs.conn.Call(ctx, req)
	if err != nil {
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}
	if out != nil {
		return res.UnmarshalPayload(out)
	}
	return nil
}

// callNoReply makes a FUSE request and doesn't expect a reply payload.
func (i *inode) callNoReply(ctx context.Context, opcode linux.FUSEOpcode, in marshal.Marshallable) error {
	return i.call(ctx, opcode, in, nil)
}

// callRaw makes a FUSE request and returns the raw response.
func (i *inode) callRaw(ctx context.Context, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*Response, error) {
	req := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), pidFromContext(ctx), i.nodeID, opcode, payload)
	return i.fs.conn.Call(ctx, req)
}
