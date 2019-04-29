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

package boot

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/strace"
)

func enableStrace(conf *Config) error {
	// We must initialize even if strace is not enabled.
	strace.Initialize()

	if !conf.Strace {
		return nil
	}

	max := conf.StraceLogSize
	if max == 0 {
		max = 1024
	}
	strace.LogMaximumSize = max

	if len(conf.StraceSyscalls) == 0 {
		strace.EnableAll(strace.SinkTypeLog)
		return nil
	}
	return strace.Enable(conf.StraceSyscalls, strace.SinkTypeLog)
}
