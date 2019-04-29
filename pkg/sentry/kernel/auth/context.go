// Copyright 2018 The gVisor Authors.
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

package auth

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

// contextID is the auth package's type for context.Context.Value keys.
type contextID int

const (
	// CtxCredentials is a Context.Value key for Credentials.
	CtxCredentials contextID = iota
)

// CredentialsFromContext returns a copy of the Credentials used by ctx, or a
// set of Credentials with no capabilities if ctx does not have Credentials.
func CredentialsFromContext(ctx context.Context) *Credentials {
	if v := ctx.Value(CtxCredentials); v != nil {
		return v.(*Credentials)
	}
	return NewAnonymousCredentials()
}
