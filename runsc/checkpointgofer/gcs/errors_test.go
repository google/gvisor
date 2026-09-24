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
	"testing"

	"golang.org/x/sys/unix"
	"google.golang.org/api/googleapi"
)

type customHTTPError struct {
	code int
}

func (e *customHTTPError) Error() string {
	return "custom http error"
}

func (e *customHTTPError) HTTPCode() int {
	return e.code
}

func TestHTTPCodeFromError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		wantCode int
		wantOk   bool
	}{
		{
			name:     "googleapi.Error 404",
			err:      &googleapi.Error{Code: 404},
			wantCode: 404,
			wantOk:   true,
		},
		{
			name:     "googleapi.Error 403",
			err:      &googleapi.Error{Code: 403},
			wantCode: 403,
			wantOk:   true,
		},
		{
			name:     "customHTTPError 401",
			err:      &customHTTPError{code: 401},
			wantCode: 401,
			wantOk:   true,
		},
		{
			name:     "standard error",
			err:      errors.New("standard error"),
			wantCode: 0,
			wantOk:   false,
		},
		{
			name:     "nil error",
			err:      nil,
			wantCode: 0,
			wantOk:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotCode, gotOk := httpCodeFromError(tc.err)
			if gotCode != tc.wantCode || gotOk != tc.wantOk {
				t.Errorf("httpCodeFromError(%v) = (%d, %t), want (%d, %t)", tc.err, gotCode, gotOk, tc.wantCode, tc.wantOk)
			}
		})
	}
}

func TestIsNotFoundCode(t *testing.T) {
	if !isNotFoundCode(404) {
		t.Errorf("isNotFoundCode(404) = false, want true")
	}
	for _, code := range []int{200, 400, 401, 403, 408, 416, 429, 500, 503} {
		if isNotFoundCode(code) {
			t.Errorf("isNotFoundCode(%d) = true, want false", code)
		}
	}
}

func TestIsPermissionDeniedCode(t *testing.T) {
	for _, code := range []int{401, 403} {
		if !isPermissionDeniedCode(code) {
			t.Errorf("isPermissionDeniedCode(%d) = false, want true", code)
		}
	}
	for _, code := range []int{200, 400, 404, 408, 416, 429, 500, 503} {
		if isPermissionDeniedCode(code) {
			t.Errorf("isPermissionDeniedCode(%d) = true, want false", code)
		}
	}
}

func TestMapGCSError(t *testing.T) {
	testCases := []struct {
		name      string
		err       error
		wantIsErr error
	}{
		{
			name:      "nil error",
			err:       nil,
			wantIsErr: nil,
		},
		{
			name:      "404 not found returns ENOENT",
			err:       &googleapi.Error{Code: 404, Message: "Not Found"},
			wantIsErr: unix.ENOENT,
		},
		{
			name:      "403 forbidden returns EACCES",
			err:       &googleapi.Error{Code: 403, Message: "Forbidden"},
			wantIsErr: unix.EACCES,
		},
		{
			name:      "401 unauthorized returns EACCES",
			err:       &googleapi.Error{Code: 401, Message: "Unauthorized"},
			wantIsErr: unix.EACCES,
		},
		{
			name:      "custom 404 returns ENOENT",
			err:       &customHTTPError{code: 404},
			wantIsErr: unix.ENOENT,
		},
		{
			name:      "custom 403 returns EACCES",
			err:       &customHTTPError{code: 403},
			wantIsErr: unix.EACCES,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapGCSError(tc.err, "TestOp", "test-bucket", "test-object")
			if !errors.Is(got, tc.wantIsErr) {
				t.Errorf("mapGCSError(%v) = %v, want %v", tc.err, got, tc.wantIsErr)
			}
		})
	}

	// For other errors, verify that the original error is returned unchanged.
	serverErr := &googleapi.Error{Code: 500, Message: "Internal Server Error"}
	if got := mapGCSError(serverErr, "TestOp", "test-bucket", "test-object"); got != serverErr {
		t.Errorf("mapGCSError(500) = %v, want original %v", got, serverErr)
	}

	genericErr := errors.New("generic error")
	if got := mapGCSError(genericErr, "TestOp", "test-bucket", "test-object"); got != genericErr {
		t.Errorf("mapGCSError(generic) = %v, want original %v", got, genericErr)
	}
}
