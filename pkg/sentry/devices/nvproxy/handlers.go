// Copyright 2024 The gVisor Authors.
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

package nvproxy

import (
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// errHandler is an error returned by an ioctl handler function.
type errHandler struct {
	Err string
}

// Error implements the error interface.
func (e *errHandler) Error() string {
	return e.Err
}

// ioctl handler errors.
var (
	errUndefinedHandler  = errHandler{"handler is undefined"}
	errMissingCapability = errHandler{"missing capability"}
)

type frontendIoctlHandler struct {
	// handler is the function to call if a capability in capSet is enabled.
	handler func(*frontendIoctlState) (uintptr, error)
	// capSet is a bitmask of capabilities that this handler is available for.
	capSet nvconf.DriverCaps
}

// feHandler returns a frontendIoctlHandler that wraps the given function.
// The handler will be called if any of the given capabilities are enabled.
func feHandler(handler func(*frontendIoctlState) (uintptr, error), caps nvconf.DriverCaps) frontendIoctlHandler {
	return frontendIoctlHandler{
		handler: handler,
		capSet:  caps,
	}
}

// handle calls the handler if the capability is enabled.
// Returns errMissingCapability if the caller is missing the required
// capabilities for this handler.
// Returns errUndefinedHandler if the handler does not exist.
func (h frontendIoctlHandler) handle(fi *frontendIoctlState) (uintptr, error) {
	if h.handler == nil {
		return 0, &errUndefinedHandler
	}
	if h.capSet&fi.fd.dev.nvp.capsEnabled == 0 {
		return 0, &errMissingCapability
	}
	return h.handler(fi)
}

type controlCmdHandler struct {
	// handler is the function to call if a capability in capSet is enabled.
	handler func(*frontendIoctlState, *nvgpu.NVOS54Parameters) (uintptr, error)
	// capSet is a bitmask of capabilities that this handler is available for.
	capSet nvconf.DriverCaps
}

// ctrlHandler returns a controlCmdHandler that wraps the given function.
// The handler will be called if any of the given capabilities are enabled.
func ctrlHandler(handler func(*frontendIoctlState, *nvgpu.NVOS54Parameters) (uintptr, error), caps nvconf.DriverCaps) controlCmdHandler {
	return controlCmdHandler{
		handler: handler,
		capSet:  caps,
	}
}

// handle calls the handler if the capability is enabled.
// Returns errMissingCapability if the caller is missing the required
// capabilities for this handler.
// Returns errUndefinedHandler if the handler does not exist.
func (h controlCmdHandler) handle(fi *frontendIoctlState, params *nvgpu.NVOS54Parameters) (uintptr, error) {
	if h.handler == nil {
		return 0, &errUndefinedHandler
	}
	if h.capSet&fi.fd.dev.nvp.capsEnabled == 0 {
		return 0, &errMissingCapability
	}
	return h.handler(fi, params)
}

type allocationClassHandler struct {
	// handler is the function to call if a capability in capSet is enabled.
	handler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error)
	// capSet is a bitmask of capabilities that this handler is available for.
	capSet nvconf.DriverCaps
}

// allocHandler returns a allocationClassHandler that wraps the given function.
// The handler will be called if any of the given capabilities are enabled.
func allocHandler(handler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error), caps nvconf.DriverCaps) allocationClassHandler {
	return allocationClassHandler{
		handler: handler,
		capSet:  caps,
	}
}

// handle calls the handler if the capability is enabled.
// Returns errMissingCapability if the caller is missing the required
// capabilities for this handler.
// Returns errUndefinedHandler if the handler does not exist.
func (h allocationClassHandler) handle(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64Parameters, isNVOS64 bool) (uintptr, error) {
	if h.handler == nil {
		return 0, &errUndefinedHandler
	}
	if h.capSet&fi.fd.dev.nvp.capsEnabled == 0 {
		return 0, &errMissingCapability
	}
	return h.handler(fi, ioctlParams, isNVOS64)
}

type uvmIoctlHandler struct {
	// handler is the function to call if a capability in capSet is enabled.
	handler func(*uvmIoctlState) (uintptr, error)
	// capSet is a bitmask of capabilities that this handler is available for.
	capSet nvconf.DriverCaps
}

// uvmHandler returns a uvmIoctlHandler that wraps the given function.
// The handler will be called if any of the given capabilities are enabled.
func uvmHandler(handler func(*uvmIoctlState) (uintptr, error), caps nvconf.DriverCaps) uvmIoctlHandler {
	return uvmIoctlHandler{
		handler: handler,
		capSet:  caps,
	}
}

// handle calls the handler if the capability is enabled.
// Returns errMissingCapability if the caller is missing the required
// capabilities for this handler.
// Returns errUndefinedHandler if the handler does not exist.
func (h uvmIoctlHandler) handle(ui *uvmIoctlState) (uintptr, error) {
	if h.handler == nil {
		return 0, &errUndefinedHandler
	}
	if h.capSet&ui.fd.dev.nvp.capsEnabled == 0 {
		return 0, &errMissingCapability
	}
	return h.handler(ui)
}
