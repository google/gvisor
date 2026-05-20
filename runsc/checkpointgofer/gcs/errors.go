// Copyright 2025 The gVisor Authors.
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

package gcs

import (
	"errors"
	"io"
	"net"
	"net/url"
	"strings"

	"google.golang.org/api/googleapi"
)

// HTTP status codes returned by GCS:
// https://cloud.google.com/storage/docs/json_api/v1/status-codes#standardcodes
const (
	// statusForbidden is returned by the storage API due to various
	// authorization failures.
	statusForbidden = 403

	// statusRangeNotSatisfiable is returned by the storage API if the first
	// byte position of a requested range is greater than the length of the
	// requested resource.
	statusRangeNotSatisfiable = 416

	// statusRequestTimeout is returned by the storage API if the
	// upload connection was broken. The request should be retried.
	statusRequestTimeout = 408

	// statusTooManyRequests is returned by the storage API if the
	// per-project limits have been temporarily exceeded. The request
	// should be retried.
	statusTooManyRequests = 429

	// statusUnauthorized is returned by the storage API due to various
	// authorization failures.
	statusUnauthorized = 401
)

func httpCodeFromError(err error) (int, bool) {
	if err, ok := err.(*googleapi.Error); ok {
		return err.Code, true
	}
	// Handle gax-go's apierror.APIError:
	if err, ok := err.(interface{ HTTPCode() int }); ok {
		return err.HTTPCode(), true
	}
	return 0, false
}

func isPermissionDeniedCode(code int) bool {
	return code == statusForbidden || code == statusUnauthorized
}

func shouldRetry(err error) bool {
	// This is equivalent to shouldRetry() from
	// https://github.com/googleapis/google-api-go-client/blob/main/internal/gensupport/retry.go.
	if code, ok := httpCodeFromError(err); ok {
		if 500 <= code || code <= 599 {
			return true
		}
		if code == statusTooManyRequests || code == statusRequestTimeout {
			return true
		}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	switch e := err.(type) {
	case *net.OpError, *url.Error:
		// Retry socket-level errors ECONNREFUSED and ECONNRESET (from syscall).
		// Unfortunately the error type is unexported, so we resort to string
		// matching.
		retriable := []string{"connection refused", "connection reset", "broken pipe"}
		es := e.Error()
		for _, s := range retriable {
			if strings.Contains(es, s) {
				return true
			}
		}
	case interface{ Temporary() bool }:
		if e.Temporary() {
			return true
		}
	}
	// If error unwrapping is available, use this to examine wrapped
	// errors.
	if e, ok := err.(interface{ Unwrap() error }); ok {
		return shouldRetry(e.Unwrap())
	}
	return false
}
