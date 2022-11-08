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

package log

import (
	"time"

	"golang.org/x/time/rate"
)

type rateLimitedLogger struct {
	logger Logger
	limit  *rate.Limiter
}

func (rl *rateLimitedLogger) Debugf(format string, v ...any) {
	if rl.limit.Allow() {
		rl.logger.Debugf(format, v...)
	}
}

func (rl *rateLimitedLogger) Infof(format string, v ...any) {
	if rl.limit.Allow() {
		rl.logger.Infof(format, v...)
	}
}

func (rl *rateLimitedLogger) Warningf(format string, v ...any) {
	if rl.limit.Allow() {
		rl.logger.Warningf(format, v...)
	}
}

func (rl *rateLimitedLogger) IsLogging(level Level) bool {
	return rl.logger.IsLogging(level)
}

// BasicRateLimitedLogger returns a Logger that logs to the global logger no
// more than once per the provided duration.
func BasicRateLimitedLogger(every time.Duration) Logger {
	return RateLimitedLogger(Log(), every)
}

// RateLimitedLogger returns a Logger that logs to the provided logger no more
// than once per the provided duration.
func RateLimitedLogger(logger Logger, every time.Duration) Logger {
	return &rateLimitedLogger{
		logger: logger,
		limit:  rate.NewLimiter(rate.Every(every), 1),
	}
}
