// Copyright 2021 The gVisor Authors.
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

package utils

import (
	"context"
	"errors"
	"fmt"

	"github.com/containerd/containerd/errdefs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrToGRPC wraps containerd's ToGRPC error mapper which depends on
// github.com/pkg/errors to work correctly. Once we upgrade to containerd v1.4,
// this function can go away and we can use errdefs.ToGRPC directly instead.
//
// TODO(gvisor.dev/issue/6232): Remove after upgrading to containerd v1.4
func ErrToGRPC(err error) error {
	return errToGRPCMsg(err, err.Error())
}

// ErrToGRPCf maps the error to grpc error codes, assembling the formatting
// string and combining it with the target error string.
//
// TODO(gvisor.dev/issue/6232): Remove after upgrading to containerd v1.4
func ErrToGRPCf(err error, format string, args ...interface{}) error {
	formatted := fmt.Sprintf(format, args...)
	msg := fmt.Sprintf("%s: %s", formatted, err.Error())
	return errToGRPCMsg(err, msg)
}

func errToGRPCMsg(err error, msg string) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}

	switch {
	case errors.Is(err, errdefs.ErrInvalidArgument):
		return status.Errorf(codes.InvalidArgument, msg)
	case errors.Is(err, errdefs.ErrNotFound):
		return status.Errorf(codes.NotFound, msg)
	case errors.Is(err, errdefs.ErrAlreadyExists):
		return status.Errorf(codes.AlreadyExists, msg)
	case errors.Is(err, errdefs.ErrFailedPrecondition):
		return status.Errorf(codes.FailedPrecondition, msg)
	case errors.Is(err, errdefs.ErrUnavailable):
		return status.Errorf(codes.Unavailable, msg)
	case errors.Is(err, errdefs.ErrNotImplemented):
		return status.Errorf(codes.Unimplemented, msg)
	case errors.Is(err, context.Canceled):
		return status.Errorf(codes.Canceled, msg)
	case errors.Is(err, context.DeadlineExceeded):
		return status.Errorf(codes.DeadlineExceeded, msg)
	}

	return errdefs.ToGRPC(err)
}
