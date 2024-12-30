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

// Package sniffer parses the output of the ioctl hook.
package sniffer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	pb "gvisor.dev/gvisor/tools/ioctl_sniffer/ioctl_go_proto"
)

var (
	uvmDevPath    = "/dev/nvidia-uvm"
	ctlDevPath    = "/dev/nvidiactl"
	deviceDevPath = regexp.MustCompile(`/dev/nvidia(\d+)`)
)

// ioctlClass is the class of the ioctl. It mainly corresponds to the various
// parts where nvproxy supports branches.
type ioctlClass uint32

const (
	frontend ioctlClass = iota
	uvm
	control // Implies NV_ESC_RM_CONTROL frontend ioctl.
	alloc   // Implies NV_ESC_RM_ALLOC frontend ioctl.
	unknown // Implies unsupported Nvidia device file.
	_numClasses
)

func (c ioctlClass) String() string {
	switch c {
	case frontend:
		return "Frontend"
	case uvm:
		return "UVM"
	case control:
		return "Control"
	case alloc:
		return "Alloc"
	default:
		return "Unknown"
	}
}

// ioctlSubclass represents an instance of a given ioctlClass.
// - For frontend and uvm ioctls, this is IOC_NR(request).
// - For NV_ESC_RM_CONTROL frontend ioctl, this is the control command number.
// - For NV_ESC_RM_ALLOC frontend ioctl, this is the alloc class.
type ioctlSubclass uint32

var (
	supportedIoctls         [_numClasses]map[uint32]struct{}
	crashOnUnsupportedIoctl bool
)

// Ioctl contains the parsed ioctl protobuf information.
type Ioctl struct {
	pb       *pb.Ioctl
	class    ioctlClass
	subclass ioctlSubclass
}

// IsSupported returns true if the ioctl is supported by nvproxy.
func (i Ioctl) IsSupported() bool {
	if i.class == control && i.subclass&nvgpu.RM_GSS_LEGACY_MASK != 0 {
		// Legacy ioctls are a special case where nvproxy passes them through unconditionally,
		// since they are undocumented and unlikely to contain problematic arguments.
		return true
	}
	_, ok := supportedIoctls[i.class][uint32(i.subclass)]
	return ok
}

func (i Ioctl) String() string {
	switch i.class {
	case control:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=NV_ESC_RM_CONTROL, cmd=%#x] => ret=%d",
			i.class, i.pb.GetRequest(), i.subclass, i.pb.GetRet())
	case alloc:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=NV_ESC_RM_ALLOC, hClass=%#x] => ret=%d",
			i.class, i.pb.GetRequest(), i.subclass, i.pb.GetRet())
	case frontend:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=%#x, size=%d] => ret=%d",
			i.class, i.pb.GetRequest(), i.subclass, len(i.pb.GetArgData()), i.pb.GetRet())
	case uvm:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=%#x] => ret=%d",
			i.class, i.pb.GetRequest(), i.subclass, i.pb.GetRet())
	case unknown:
		return fmt.Sprintf("%s ioctl: path=%s request=%#x [nr=%#x] => ret=%d",
			i.class, i.pb.GetFdPath(), i.pb.GetRequest(), i.subclass, i.pb.GetRet())
	}
	panic("unreachable")
}

// Results contains the list of unsupported ioctls.
type Results struct {
	unsupported [_numClasses]map[ioctlSubclass]Ioctl
}

// NewResults creates a new Results object.
func NewResults() *Results {
	return &Results{
		unsupported: [_numClasses]map[ioctlSubclass]Ioctl{},
	}
}

// AddUnsupportedIoctl adds an unsupported ioctl to the results.
func (r *Results) AddUnsupportedIoctl(ioctl Ioctl) {
	if r.unsupported[ioctl.class] == nil {
		r.unsupported[ioctl.class] = make(map[ioctlSubclass]Ioctl)
	}
	r.unsupported[ioctl.class][ioctl.subclass] = ioctl
}

func (r *Results) String() string {
	// We will rarely print out the results, so allocating a new strings.Builder
	// each time is fine.
	b := new(strings.Builder)

	for class := ioctlClass(0); class < _numClasses; class++ {
		if len(r.unsupported[class]) == 0 {
			fmt.Fprintf(b, "%v: None\n", class)
			continue
		}

		fmt.Fprintf(b, "%v:\n", class)
		for _, ioctl := range r.unsupported[class] {
			fmt.Fprintf(b, "\t%v\n", ioctl)
		}
	}

	return b.String()
}

// HasUnsupportedIoctl returns true if there are any unsupported ioctls.
func (r *Results) HasUnsupportedIoctl() bool {
	for _, m := range r.unsupported {
		if len(m) != 0 {
			return true
		}
	}
	return false
}

// Merge merges the results from another Results object into this one.
func (r *Results) Merge(other *Results) {
	for class := ioctlClass(0); class < _numClasses; class++ {
		for _, ioctl := range other.unsupported[class] {
			r.AddUnsupportedIoctl(ioctl)
		}
	}
}

// Init reads from nvproxy and sets up the supported ioctl maps.
func Init() error {
	nvproxy.Init()

	// Load the ABI for the host driver.
	driverVerStr, err := nvproxy.HostDriverVersion()
	if err != nil {
		return fmt.Errorf("failed to get host driver version: %w", err)
	}
	driverVer, err := nvproxy.DriverVersionFrom(driverVerStr)
	if err != nil {
		return fmt.Errorf("failed to parse host driver version: %w", err)
	}

	log.Debugf("Host driver version: %v", driverVer)

	suppFrontendIoctls, suppUvmIoctls, suppControlCmds, suppAllocClasses, ok := nvproxy.SupportedIoctls(driverVer)
	if !ok {
		return fmt.Errorf("host driver version %s is not supported", driverVer)
	}
	supportedIoctls = [_numClasses]map[uint32]struct{}{
		frontend: suppFrontendIoctls,
		uvm:      suppUvmIoctls,
		control:  suppControlCmds,
		alloc:    suppAllocClasses,
		unknown:  make(map[uint32]struct{}),
	}
	if os.Getenv("GVISOR_IOCTL_SNIFFER_ENFORCE_COMPATIBILITY") == "INSTANT" {
		crashOnUnsupportedIoctl = true
	}

	return nil
}

// ReadHookOutput reads the output of the ioctl hook until an EOF is reached.
func (c Connection) ReadHookOutput(ctx context.Context) *Results {
	res := NewResults()
	for {
		ioctlPB, err := c.ReadIoctlProto(ctx)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warningf("Error reading ioctl proto: %v", err)
			}
			break
		}

		// Parse the protobuf
		ioctl, err := ParseIoctlOutput(ioctlPB)
		if err != nil {
			log.Warningf("Error parsing ioctl %v: %v", ioctlPB, err)
			continue
		}

		log.Debugf("%s", ioctl)

		if !ioctl.IsSupported() {
			res.AddUnsupportedIoctl(ioctl)
			if crashOnUnsupportedIoctl {
				log.Warningf("Unsupported ioctl found; crashing immediately: %v", ioctl)
				os.Exit(1)
			}
		}
	}
	return res
}

// ParseIoctlOutput parses an ioctl protobuf from the ioctl hook.
func ParseIoctlOutput(ioctl *pb.Ioctl) (Ioctl, error) {
	parsedIoctl := Ioctl{pb: ioctl}

	// Categorize and do class-specific parsing.
	path := ioctl.GetFdPath()
	switch {
	case path == uvmDevPath:
		parsedIoctl.class = uvm
		parsedIoctl.subclass = ioctlSubclass(ioctl.GetRequest())
	case path == ctlDevPath || deviceDevPath.MatchString(path):
		parsedIoctl.class = frontend
		parsedIoctl.subclass = ioctlSubclass(linux.IOC_NR(uint32(ioctl.GetRequest())))

		switch parsedIoctl.subclass {
		case nvgpu.NV_ESC_RM_CONTROL:
			data := ioctl.GetArgData()
			if uint32(len(data)) != nvgpu.SizeofNVOS54Parameters {
				return parsedIoctl, fmt.Errorf("unexpected number of bytes")
			}
			var ioctlParams nvgpu.NVOS54_PARAMETERS
			ioctlParams.UnmarshalBytes(data)

			parsedIoctl.class = control
			parsedIoctl.subclass = ioctlSubclass(ioctlParams.Cmd)
		case nvgpu.NV_ESC_RM_ALLOC:
			data := ioctl.GetArgData()
			var isNVOS64 bool
			switch uint32(len(data)) {
			case nvgpu.SizeofNVOS21Parameters:
			case nvgpu.SizeofNVOS64Parameters:
				isNVOS64 = true
			default:
				return parsedIoctl, fmt.Errorf("unexpected number of bytes")
			}
			ioctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
			ioctlParams.UnmarshalBytes(data)

			parsedIoctl.class = alloc
			parsedIoctl.subclass = ioctlSubclass(ioctlParams.GetHClass())
		}
	default:
		parsedIoctl.class = unknown
		parsedIoctl.subclass = ioctlSubclass(linux.IOC_NR(uint32(ioctl.GetRequest())))
	}

	return parsedIoctl, nil
}
