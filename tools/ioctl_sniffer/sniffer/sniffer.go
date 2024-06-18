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
	"errors"
	"fmt"
	"io"
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

const (
	frontend = iota
	uvm
	control
	alloc
	unknown
)

// ioctlClass is the class of the ioctl as defined above.
type ioctlClass uint32

// ioctlNr is the command number of the ioctl.
type ioctlNr uint32

// controlCommand is the control command, specifically for the NV_ESC_RM_CONTROL ioctl.
type controlCommand uint32

// allocClass is the alloc class, specifically for the NV_ESC_RM_ALLOC ioctl.
type allocClass uint32

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

var (
	suppFrontendIoctls, suppUvmIoctls, suppControlCmds, suppAllocClasses map[uint32]struct{}
)

// Ioctl contains the parsed ioctl protobuf information.
type Ioctl struct {
	pb     *pb.Ioctl
	class  ioctlClass
	nr     ioctlNr
	cmd    controlCommand // Control ioctls only.
	hClass allocClass     // Alloc ioctls only.
}

// IsSupported returns true if the ioctl is supported by nvproxy.
func (i Ioctl) IsSupported() bool {
	switch i.class {
	case frontend:
		_, ok := suppFrontendIoctls[uint32(i.nr)]
		return ok
	case uvm:
		_, ok := suppUvmIoctls[uint32(i.nr)]
		return ok
	case control:
		_, ok := suppControlCmds[uint32(i.cmd)]
		return ok
	case alloc:
		_, ok := suppAllocClasses[uint32(i.hClass)]
		return ok
	default:
		return false
	}
}

func (i Ioctl) String() string {
	switch i.class {
	case control:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=%#x (%d), cmd=%#x (%d)] => ret=%d",
			i.class, i.pb.GetRequest(), i.nr, i.nr, i.cmd, i.cmd, i.pb.GetRet())
	case alloc:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=%#x (%d), hClass=%#x (%d)] => ret=%d",
			i.class, i.pb.GetRequest(), i.nr, i.nr, i.hClass, i.hClass, i.pb.GetRet())
	default:
		return fmt.Sprintf("%s ioctl: request=%#x [nr=%#x (%d), size=%d] => ret=%d",
			i.class, i.pb.GetRequest(), i.nr, i.nr, len(i.pb.GetArgData()), i.pb.GetRet())
	}
}

// Results contains the list of unsupported ioctls.
type Results struct {
	unsupportedControl map[controlCommand]Ioctl
	unsupportedAlloc   map[allocClass]Ioctl
	unsupportedOther   map[ioctlClass]map[ioctlNr]Ioctl
}

// NewResults creates a new Results object.
func NewResults() *Results {
	return &Results{
		unsupportedControl: make(map[controlCommand]Ioctl),
		unsupportedAlloc:   make(map[allocClass]Ioctl),
		unsupportedOther:   make(map[ioctlClass]map[ioctlNr]Ioctl),
	}
}

// AddUnsupportedIoctl adds an unsupported ioctl to the results.
func (r *Results) AddUnsupportedIoctl(ioctl Ioctl) {
	switch ioctl.class {
	case control:
		r.unsupportedControl[ioctl.cmd] = ioctl
	case alloc:
		r.unsupportedAlloc[ioctl.hClass] = ioctl
	default:
		if r.unsupportedOther[ioctl.class] == nil {
			r.unsupportedOther[ioctl.class] = make(map[ioctlNr]Ioctl)
		}
		r.unsupportedOther[ioctl.class][ioctl.nr] = ioctl
	}
}

func printIoctls[T comparable](b *strings.Builder, class ioctlClass, m map[T]Ioctl) {
	if len(m) == 0 {
		fmt.Fprintf(b, "%v: None\n", class)
		return
	}

	fmt.Fprintf(b, "%v:\n", class)
	for _, ioctl := range m {
		fmt.Fprintf(b, "\t%v\n", ioctl)
	}
}

func (r *Results) String() string {
	// We will rarely print out the results, so allocating a new strings.Builder
	// each time is fine.
	b := new(strings.Builder)

	fmt.Fprintln(b, "============== Unsupported ioctls ==============")
	printIoctls(b, frontend, r.unsupportedOther[frontend])
	printIoctls(b, uvm, r.unsupportedOther[uvm])
	printIoctls(b, control, r.unsupportedControl)
	printIoctls(b, alloc, r.unsupportedAlloc)
	printIoctls(b, unknown, r.unsupportedOther[unknown])

	return b.String()
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

	log.Infof("Host driver version: %v", driverVer)

	var ok bool
	suppFrontendIoctls, suppUvmIoctls, suppControlCmds, suppAllocClasses, ok = nvproxy.SupportedIoctls(driverVer)
	if !ok {
		return fmt.Errorf("host driver version %s is not supported", driverVer)
	}

	return nil
}

// ReadHookOutput reads the output of the ioctl hook until an EOF is reached.
func ReadHookOutput(r io.Reader) *Results {
	res := NewResults()
	for {
		ioctlPB, err := ReadIoctlProto(r)
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
		}
	}
	return res
}

// ParseIoctlOutput parses an ioctl protobuf from the ioctl hook.
func ParseIoctlOutput(ioctl *pb.Ioctl) (Ioctl, error) {
	parsedIoctl := Ioctl{pb: ioctl}

	// Categorize and do class-specific parsing.
	switch {
	case ioctl.GetFdPath() == uvmDevPath:
		parsedIoctl.class = uvm
		parsedIoctl.nr = ioctlNr(ioctl.GetRequest())
	case ioctl.GetFdPath() == ctlDevPath || deviceDevPath.MatchString(ioctl.GetFdPath()):
		parsedIoctl.nr = ioctlNr(linux.IOC_NR(uint32(ioctl.GetRequest())))

		switch parsedIoctl.nr {
		case nvgpu.NV_ESC_RM_CONTROL:
			data := ioctl.GetArgData()
			if uint32(len(data)) != nvgpu.SizeofNVOS54Parameters {
				return parsedIoctl, fmt.Errorf("unexpected number of bytes")
			}
			var ioctlParams nvgpu.NVOS54Parameters
			ioctlParams.UnmarshalBytes(data)

			parsedIoctl.class = control
			parsedIoctl.cmd = controlCommand(ioctlParams.Cmd)
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
			parsedIoctl.hClass = allocClass(ioctlParams.GetHClass())
		default:
			parsedIoctl.class = frontend
		}
	default:
		parsedIoctl.class = unknown
		parsedIoctl.nr = ioctlNr(linux.IOC_NR(uint32(ioctl.GetRequest())))
	}

	return parsedIoctl, nil
}
