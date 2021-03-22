// Copyright 2020 The gVisor Authors.
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

// Package runner starts docker containers and networking for a packetimpact test.
package runner

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/packetimpact/netdevs"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

// stringList implements flag.Value.
type stringList []string

// String implements flag.Value.String.
func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

// Set implements flag.Value.Set.
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var (
	native          = false
	testbenchBinary = ""
	tshark          = false
	extraTestArgs   = stringList{}
	expectFailure   = false
	numDUTs         = 1

	// DUTAddr is the IP addres for DUT.
	DUTAddr       = net.IPv4(0, 0, 0, 10)
	testbenchAddr = net.IPv4(0, 0, 0, 20)
)

// RegisterFlags defines flags and associates them with the package-level
// exported variables above. It should be called by tests in their init
// functions.
func RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&native, "native", false, "whether the test should be run natively")
	fs.StringVar(&testbenchBinary, "testbench_binary", "", "path to the testbench binary")
	fs.BoolVar(&tshark, "tshark", false, "use more verbose tshark in logs instead of tcpdump")
	fs.Var(&extraTestArgs, "extra_test_arg", "extra arguments to pass to the testbench")
	fs.BoolVar(&expectFailure, "expect_failure", false, "expect that the test will fail when run")
	fs.IntVar(&numDUTs, "num_duts", numDUTs, "the number of duts to create")
}

const (
	// CtrlPort is the port that posix_server listens on.
	CtrlPort uint16 = 40000
	// testOutputDir is the directory in each container that holds test output.
	testOutputDir = "/tmp/testoutput"
)

// logger implements testutil.Logger.
//
// Labels logs based on their source and formats multi-line logs.
type logger string

// Name implements testutil.Logger.Name.
func (l logger) Name() string {
	return string(l)
}

// Logf implements testutil.Logger.Logf.
func (l logger) Logf(format string, args ...interface{}) {
	lines := strings.Split(fmt.Sprintf(format, args...), "\n")
	log.Printf("%s: %s", l, lines[0])
	for _, line := range lines[1:] {
		log.Printf("%*s  %s", len(l), "", line)
	}
}

// dutInfo encapsulates all the essential information to set up testbench
// container.
type dutInfo struct {
	dut              DUT
	ctrlNet, testNet *dockerutil.Network
	netInfo          *testbench.DUTTestNet
	uname            *testbench.DUTUname
}

// setUpDUT will set up one DUT and return information for setting up the
// container for testbench.
func setUpDUT(ctx context.Context, t *testing.T, id int, mkDevice func(*dockerutil.Container) DUT) (dutInfo, error) {
	// Create the networks needed for the test. One control network is needed
	// for the gRPC control packets and one test network on which to transmit
	// the test packets.
	var info dutInfo
	ctrlNet := dockerutil.NewNetwork(ctx, logger("ctrlNet"))
	testNet := dockerutil.NewNetwork(ctx, logger("testNet"))
	for _, dn := range []*dockerutil.Network{ctrlNet, testNet} {
		for {
			if err := createDockerNetwork(ctx, dn); err != nil {
				t.Log("creating docker network:", err)
				const wait = 100 * time.Millisecond
				t.Logf("sleeping %s and will try creating docker network again", wait)
				// This can fail if another docker network claimed the same IP so we
				// will just try again.
				time.Sleep(wait)
				continue
			}
			break
		}
		dn := dn
		t.Cleanup(func() {
			if err := dn.Cleanup(ctx); err != nil {
				t.Errorf("failed to cleanup network %s: %s", dn.Name, err)
			}
		})
		// Sanity check.
		if inspect, err := dn.Inspect(ctx); err != nil {
			return dutInfo{}, fmt.Errorf("failed to inspect network %s: %w", dn.Name, err)
		} else if inspect.Name != dn.Name {
			return dutInfo{}, fmt.Errorf("name mismatch for network want: %s got: %s", dn.Name, inspect.Name)
		}
	}
	info.ctrlNet = ctrlNet
	info.testNet = testNet

	// Create the Docker container for the DUT.
	makeContainer := dockerutil.MakeContainer
	if native {
		makeContainer = dockerutil.MakeNativeContainer
	}
	dutContainer := makeContainer(ctx, logger(fmt.Sprintf("dut-%d", id)))
	t.Cleanup(func() {
		dutContainer.CleanUp(ctx)
	})
	info.dut = mkDevice(dutContainer)

	runOpts := dockerutil.RunOpts{
		Image:  "packetimpact",
		CapAdd: []string{"NET_ADMIN"},
	}
	if _, err := MountTempDirectory(t, &runOpts, "dut-output", testOutputDir); err != nil {
		return dutInfo{}, err
	}

	ipv4PrefixLength, _ := testNet.Subnet.Mask.Size()
	remoteIPv6, remoteMAC, dutDeviceID, dutTestNetDev, err := info.dut.Prepare(ctx, t, runOpts, ctrlNet, testNet)
	if err != nil {
		return dutInfo{}, err
	}
	info.netInfo = &testbench.DUTTestNet{
		RemoteMAC:        remoteMAC,
		RemoteIPv4:       AddressInSubnet(DUTAddr, *testNet.Subnet),
		RemoteIPv6:       remoteIPv6,
		RemoteDevID:      dutDeviceID,
		RemoteDevName:    dutTestNetDev,
		LocalIPv4:        AddressInSubnet(testbenchAddr, *testNet.Subnet),
		IPv4PrefixLength: ipv4PrefixLength,
		POSIXServerIP:    AddressInSubnet(DUTAddr, *ctrlNet.Subnet),
		POSIXServerPort:  CtrlPort,
	}
	info.uname, err = info.dut.Uname(ctx)
	if err != nil {
		return dutInfo{}, fmt.Errorf("failed to get uname information on DUT: %w", err)
	}
	return info, nil
}

// TestWithDUT runs a packetimpact test with the given information.
func TestWithDUT(ctx context.Context, t *testing.T, mkDevice func(*dockerutil.Container) DUT) {
	if testbenchBinary == "" {
		t.Fatal("--testbench_binary is missing")
	}
	dockerutil.EnsureSupportedDockerVersion()

	dutInfoChan := make(chan dutInfo, numDUTs)
	errChan := make(chan error, numDUTs)
	var dockerNetworks []*dockerutil.Network
	var dutInfos []*testbench.DUTInfo
	var duts []DUT

	setUpCtx, cancelSetup := context.WithCancel(ctx)
	t.Cleanup(cancelSetup)
	for i := 0; i < numDUTs; i++ {
		go func(i int) {
			info, err := setUpDUT(setUpCtx, t, i, mkDevice)
			if err != nil {
				errChan <- err
			} else {
				dutInfoChan <- info
			}
		}(i)
	}
	for i := 0; i < numDUTs; i++ {
		select {
		case info := <-dutInfoChan:
			dockerNetworks = append(dockerNetworks, info.ctrlNet, info.testNet)
			dutInfos = append(dutInfos, &testbench.DUTInfo{
				Net:   info.netInfo,
				Uname: info.uname,
			})
			duts = append(duts, info.dut)
		case err := <-errChan:
			t.Fatal(err)
		}
	}

	// Create the Docker container for the testbench.
	testbenchContainer := dockerutil.MakeNativeContainer(ctx, logger("testbench"))
	t.Cleanup(func() {
		testbenchContainer.CleanUp(ctx)
	})

	runOpts := dockerutil.RunOpts{
		Image:  "packetimpact",
		CapAdd: []string{"NET_ADMIN"},
	}
	if _, err := MountTempDirectory(t, &runOpts, "testbench-output", testOutputDir); err != nil {
		t.Fatal(err)
	}
	tbb := path.Base(testbenchBinary)
	containerTestbenchBinary := filepath.Join("/packetimpact", tbb)
	testbenchContainer.CopyFiles(&runOpts, "/packetimpact", filepath.Join("test/packetimpact/tests", tbb))

	if err := StartContainer(
		ctx,
		runOpts,
		testbenchContainer,
		testbenchAddr,
		dockerNetworks,
		nil, /* sysctls */
		"tail", "-f", "/dev/null",
	); err != nil {
		t.Fatalf("cannot start testbench container: %s", err)
	}

	for i := range dutInfos {
		name, info, err := deviceByIP(ctx, testbenchContainer, dutInfos[i].Net.LocalIPv4)
		if err != nil {
			t.Fatalf("failed to get the device name associated with %s: %s", dutInfos[i].Net.LocalIPv4, err)
		}
		dutInfos[i].Net.LocalDevName = name
		dutInfos[i].Net.LocalDevID = info.ID
		dutInfos[i].Net.LocalMAC = info.MAC
		localIPv6, err := getOrAssignIPv6Addr(ctx, testbenchContainer, name)
		if err != nil {
			t.Fatalf("failed to get IPV6 address on %s: %s", testbenchContainer.Name, err)
		}
		dutInfos[i].Net.LocalIPv6 = localIPv6
	}
	dutInfosBytes, err := json.Marshal(dutInfos)
	if err != nil {
		t.Fatalf("failed to marshal %v into json: %s", dutInfos, err)
	}

	baseSnifferArgs := []string{
		"tcpdump",
		"-vvv",
		"--absolute-tcp-sequence-numbers",
		"--packet-buffered",
		// Disable DNS resolution.
		"-n",
		// run tcpdump as root since the output directory is owned by root. From
		// `man tcpdump`:
		//
		// -Z user
		// --relinquish-privileges=user
		//        If tcpdump is running as root, after opening the capture device
		//        or input savefile, change the user ID to user and the group ID to
		//        the primary group of user.
		// This behavior is enabled by default (-Z tcpdump), and can be
		// disabled by -Z root.
		"-Z", "root",
	}
	if tshark {
		baseSnifferArgs = []string{
			"tshark",
			"-V",
			"-o", "tcp.check_checksum:TRUE",
			"-o", "udp.check_checksum:TRUE",
			// Disable buffering.
			"-l",
			// Disable DNS resolution.
			"-n",
		}
	}
	for _, info := range dutInfos {
		n := info.Net
		snifferArgs := append(baseSnifferArgs, "-i", n.LocalDevName)
		if !tshark {
			snifferArgs = append(
				snifferArgs,
				"-w",
				filepath.Join(testOutputDir, fmt.Sprintf("%s.pcap", n.LocalDevName)),
			)
		}
		p, err := testbenchContainer.ExecProcess(ctx, dockerutil.ExecOpts{}, snifferArgs...)
		if err != nil {
			t.Fatalf("failed to start exec a sniffer on %s: %s", n.LocalDevName, err)
		}
		t.Cleanup(func() {
			if snifferOut, err := p.Logs(); err != nil {
				t.Errorf("sniffer logs failed: %s\n%s", err, snifferOut)
			} else {
				t.Logf("sniffer logs:\n%s", snifferOut)
			}
		})
		// When the Linux kernel receives a SYN-ACK for a SYN it didn't send, it
		// will respond with an RST. In most packetimpact tests, the SYN is sent
		// by the raw socket, the kernel knows nothing about the connection, this
		// behavior will break lots of TCP related packetimpact tests. To prevent
		// this, we can install the following iptables rules. The raw socket that
		// packetimpact tests use will still be able to see everything.
		for _, bin := range []string{"iptables", "ip6tables"} {
			if logs, err := testbenchContainer.Exec(ctx, dockerutil.ExecOpts{}, bin, "-A", "INPUT", "-i", n.LocalDevName, "-p", "tcp", "-j", "DROP"); err != nil {
				t.Fatalf("unable to Exec %s on container %s: %s, logs from testbench:\n%s", bin, testbenchContainer.Name, err, logs)
			}
		}
	}

	t.Cleanup(func() {
		// Wait 1 second before killing tcpdump to give it time to flush
		// any packets. On linux tests killing it immediately can
		// sometimes result in partial pcaps.
		time.Sleep(1 * time.Second)
		if logs, err := testbenchContainer.Exec(ctx, dockerutil.ExecOpts{}, "killall", baseSnifferArgs[0]); err != nil {
			t.Errorf("failed to kill all sniffers: %s, logs: %s", err, logs)
		}
	})

	// FIXME(b/156449515): Some piece of the system has a race. The old
	// bash script version had a sleep, so we have one too. The race should
	// be fixed and this sleep removed.
	time.Sleep(time.Second)

	// Start a packetimpact test on the test bench. The packetimpact test sends
	// and receives packets and also sends POSIX socket commands to the
	// posix_server to be executed on the DUT.
	testArgs := []string{containerTestbenchBinary}
	testArgs = append(testArgs, extraTestArgs...)
	testArgs = append(testArgs,
		fmt.Sprintf("--native=%t", native),
		"--dut_infos_json", string(dutInfosBytes),
	)
	testbenchLogs, err := testbenchContainer.Exec(ctx, dockerutil.ExecOpts{}, testArgs...)
	if (err != nil) != expectFailure {
		var dutLogs string
		for i, dut := range duts {
			logs, err := dut.Logs(ctx)
			if err != nil {
				logs = fmt.Sprintf("failed to fetch DUT logs: %s", err)
			}
			dutLogs = fmt.Sprintf(`%s====== Begin of DUT-%d Logs ======

%s

====== End of DUT-%d Logs ======

`, dutLogs, i, logs, i)
		}

		t.Errorf(`test error: %v, expect failure: %t

%s====== Begin of Testbench Logs ======

%s

====== End of Testbench Logs ======`,
			err, expectFailure, dutLogs, testbenchLogs)
	}
}

// DUT describes how to setup/teardown the dut for packetimpact tests.
type DUT interface {
	// Prepare prepares the dut, starts posix_server and returns the IPv6, MAC
	// address, the interface ID, and the interface name for the testNet on DUT.
	// The t parameter is supposed to be used for t.Cleanup. Don't use it for
	// t.Fatal/FailNow functions.
	Prepare(ctx context.Context, t *testing.T, runOpts dockerutil.RunOpts, ctrlNet, testNet *dockerutil.Network) (net.IP, net.HardwareAddr, uint32, string, error)

	// Uname gathers information of DUT using command uname.
	Uname(ctx context.Context) (*testbench.DUTUname, error)

	// Logs retrieves the logs from the dut.
	Logs(ctx context.Context) (string, error)
}

// DockerDUT describes a docker based DUT.
type DockerDUT struct {
	c *dockerutil.Container
}

// NewDockerDUT creates a docker based DUT.
func NewDockerDUT(c *dockerutil.Container) DUT {
	return &DockerDUT{
		c: c,
	}
}

// Prepare implements DUT.Prepare.
func (dut *DockerDUT) Prepare(ctx context.Context, _ *testing.T, runOpts dockerutil.RunOpts, ctrlNet, testNet *dockerutil.Network) (net.IP, net.HardwareAddr, uint32, string, error) {
	const containerPosixServerBinary = "/packetimpact/posix_server"
	dut.c.CopyFiles(&runOpts, "/packetimpact", "test/packetimpact/dut/posix_server")

	if err := StartContainer(
		ctx,
		runOpts,
		dut.c,
		DUTAddr,
		[]*dockerutil.Network{ctrlNet, testNet},
		map[string]string{
			// This enables creating ICMP sockets on Linux.
			"net.ipv4.ping_group_range": "0 0",
		},
		containerPosixServerBinary,
		"--ip=0.0.0.0",
		fmt.Sprintf("--port=%d", CtrlPort),
	); err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to start docker container for DUT: %w", err)
	}

	if _, err := dut.c.WaitForOutput(ctx, "Server listening.*\n", 60*time.Second); err != nil {
		return nil, nil, 0, "", fmt.Errorf("%s on container %s never listened: %s", containerPosixServerBinary, dut.c.Name, err)
	}

	dutTestDevice, dutDeviceInfo, err := deviceByIP(ctx, dut.c, AddressInSubnet(DUTAddr, *testNet.Subnet))
	if err != nil {
		return nil, nil, 0, "", err
	}

	remoteIPv6, err := getOrAssignIPv6Addr(ctx, dut.c, dutTestDevice)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("failed to get IPv6 address on %s: %s", dut.c.Name, err)
	}
	const testNetDev = "eth2"

	return remoteIPv6, dutDeviceInfo.MAC, dutDeviceInfo.ID, testNetDev, nil
}

// Uname implements DUT.Uname.
func (dut *DockerDUT) Uname(ctx context.Context) (*testbench.DUTUname, error) {
	machine, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "uname", "-m")
	if err != nil {
		return nil, err
	}
	kernelRelease, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "uname", "-r")
	if err != nil {
		return nil, err
	}
	kernelVersion, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "uname", "-v")
	if err != nil {
		return nil, err
	}
	kernelName, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "uname", "-s")
	if err != nil {
		return nil, err
	}
	// TODO(gvisor.dev/issues/5586): -o is not supported on macOS.
	operatingSystem, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "uname", "-o")
	if err != nil {
		return nil, err
	}
	return &testbench.DUTUname{
		Machine:         strings.TrimRight(machine, "\n"),
		KernelName:      strings.TrimRight(kernelName, "\n"),
		KernelRelease:   strings.TrimRight(kernelRelease, "\n"),
		KernelVersion:   strings.TrimRight(kernelVersion, "\n"),
		OperatingSystem: strings.TrimRight(operatingSystem, "\n"),
	}, nil
}

// Logs implements DUT.Logs.
func (dut *DockerDUT) Logs(ctx context.Context) (string, error) {
	logs, err := dut.c.Logs(ctx)
	if err != nil {
		return "", err
	}
	return logs, nil
}

// AddNetworks connects docker network with the container and assigns the specific IP.
func AddNetworks(ctx context.Context, d *dockerutil.Container, addr net.IP, networks []*dockerutil.Network) error {
	for _, dn := range networks {
		ip := AddressInSubnet(addr, *dn.Subnet)
		// Connect to the network with the specified IP address.
		if err := dn.Connect(ctx, d, ip.String(), ""); err != nil {
			return fmt.Errorf("unable to connect container %s to network %s: %w", d.Name, dn.Name, err)
		}
	}
	return nil
}

// AddressInSubnet combines the subnet provided with the address and returns a
// new address. The return address bits come from the subnet where the mask is
// 1 and from the ip address where the mask is 0.
func AddressInSubnet(addr net.IP, subnet net.IPNet) net.IP {
	var octets net.IP
	for i := 0; i < 4; i++ {
		octets = append(octets, (subnet.IP.To4()[i]&subnet.Mask[i])+(addr.To4()[i]&(^subnet.Mask[i])))
	}
	return octets
}

// devicesInfo will run "ip addr show" on the container and parse the output
// to a map[string]netdevs.DeviceInfo.
func devicesInfo(ctx context.Context, d *dockerutil.Container) (map[string]netdevs.DeviceInfo, error) {
	out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "ip", "addr", "show")
	if err != nil {
		return map[string]netdevs.DeviceInfo{}, fmt.Errorf("listing devices on %s container: %w\n%s", d.Name, err, out)
	}
	devs, err := netdevs.ParseDevices(out)
	if err != nil {
		return map[string]netdevs.DeviceInfo{}, fmt.Errorf("parsing devices from %s container: %w\n%s", d.Name, err, out)
	}
	return devs, nil
}

// deviceByIP finds a deviceInfo and device name from an IP address.
func deviceByIP(ctx context.Context, d *dockerutil.Container, ip net.IP) (string, netdevs.DeviceInfo, error) {
	devs, err := devicesInfo(ctx, d)
	if err != nil {
		return "", netdevs.DeviceInfo{}, err
	}
	testDevice, deviceInfo, err := netdevs.FindDeviceByIP(ip, devs)
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("can't find deviceInfo for container %s: %w", d.Name, err)
	}
	return testDevice, deviceInfo, nil
}

// getOrAssignIPv6Addr will try to get the IPv6 address for the interface; if an
// address was not assigned, a link-local address based on MAC will be assigned
// to that interface.
func getOrAssignIPv6Addr(ctx context.Context, d *dockerutil.Container, iface string) (net.IP, error) {
	devs, err := devicesInfo(ctx, d)
	if err != nil {
		return net.IP{}, err
	}
	info := devs[iface]
	if info.IPv6Addr != nil {
		return info.IPv6Addr, nil
	}
	if info.MAC == nil {
		return nil, fmt.Errorf("unable to find MAC address of %s", iface)
	}
	if logs, err := d.Exec(ctx, dockerutil.ExecOpts{}, "ip", "addr", "add", netdevs.MACToIP(info.MAC).String(), "scope", "link", "dev", iface); err != nil {
		return net.IP{}, fmt.Errorf("unable to ip addr add on container %s: %w, logs: %s", d.Name, err, logs)
	}
	// Now try again, to make sure that it worked.
	devs, err = devicesInfo(ctx, d)
	if err != nil {
		return net.IP{}, err
	}
	info = devs[iface]
	if info.IPv6Addr == nil {
		return net.IP{}, fmt.Errorf("unable to set IPv6 address on container %s", d.Name)
	}
	return info.IPv6Addr, nil
}

// createDockerNetwork makes a randomly-named network that will start with the
// namePrefix. The network will be a random /24 subnet.
func createDockerNetwork(ctx context.Context, n *dockerutil.Network) error {
	randSource := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(randSource)
	// Class C, 192.0.0.0 to 223.255.255.255, transitionally has mask 24.
	ip := net.IPv4(byte(r1.Intn(224-192)+192), byte(r1.Intn(256)), byte(r1.Intn(256)), 0)
	n.Subnet = &net.IPNet{
		IP:   ip,
		Mask: ip.DefaultMask(),
	}
	return n.Create(ctx)
}

// StartContainer will create a container instance from runOpts, connect it
// with the specified docker networks and start executing the specified cmd.
func StartContainer(ctx context.Context, runOpts dockerutil.RunOpts, c *dockerutil.Container, containerAddr net.IP, ns []*dockerutil.Network, sysctls map[string]string, cmd ...string) error {
	conf, hostconf, netconf := c.ConfigsFrom(runOpts, cmd...)
	_ = netconf
	hostconf.Sysctls = map[string]string{"net.ipv6.conf.all.disable_ipv6": "0"}
	for k, v := range sysctls {
		hostconf.Sysctls[k] = v
	}

	if err := c.CreateFrom(ctx, runOpts.Image, conf, hostconf, nil); err != nil {
		return fmt.Errorf("unable to create container %s: %w", c.Name, err)
	}

	if err := AddNetworks(ctx, c, containerAddr, ns); err != nil {
		return fmt.Errorf("unable to connect the container with the networks: %w", err)
	}

	if err := c.Start(ctx); err != nil {
		return fmt.Errorf("unable to start container %s: %w", c.Name, err)
	}
	return nil
}

// MountTempDirectory creates a temporary directory on host with the template
// and then mounts it into the container under the name provided. The temporary
// directory name is returned. Content in that directory will be copied to
// TEST_UNDECLARED_OUTPUTS_DIR in cleanup phase.
func MountTempDirectory(t *testing.T, runOpts *dockerutil.RunOpts, hostDirTemplate, containerDir string) (string, error) {
	t.Helper()
	tmpDir, err := ioutil.TempDir("", hostDirTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to create a temp dir: %w", err)
	}
	t.Cleanup(func() {
		if err := exec.Command("/bin/cp", "-r", tmpDir, os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR")).Run(); err != nil {
			t.Errorf("unable to copy container output files: %s", err)
		}
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove tmpDir %s: %s", tmpDir, err)
		}
	})
	runOpts.Mounts = append(runOpts.Mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   tmpDir,
		Target:   containerDir,
		ReadOnly: false,
	})
	return tmpDir, nil
}
