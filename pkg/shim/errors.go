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

package shim

import (
	"context"
	"errors"

	"github.com/containerd/containerd/errdefs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errToGRPC wraps containerd's ToGRPC error mapper which depends on
// github.com/pkg/errors to work correctly. Once we upgrade to containerd v1.4,
// this function can go away and we can use errdefs.ToGRPC directly instead.
//
// TODO(gvisor.dev/issue/6232): Remove after upgrading to containerd v1.4
func errToGRPC(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}

	switch {
	case errors.Is(err, errdefs.ErrInvalidArgument):
		return status.Errorf(codes.InvalidArgument, err.Error())
	case errors.Is(err, errdefs.ErrNotFound):
		return status.Errorf(codes.NotFound, err.Error())
	case errors.Is(err, errdefs.ErrAlreadyExists):
		return status.Errorf(codes.AlreadyExists, err.Error())
	case errors.Is(err, errdefs.ErrFailedPrecondition):
		return status.Errorf(codes.FailedPrecondition, err.Error())
	case errors.Is(err, errdefs.ErrUnavailable):
		return status.Errorf(codes.Unavailable, err.Error())
	case errors.Is(err, errdefs.ErrNotImplemented):
		return status.Errorf(codes.Unimplemented, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Errorf(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Errorf(codes.DeadlineExceeded, err.Error())
	}

	return errdefs.ToGRPC(err)
}
