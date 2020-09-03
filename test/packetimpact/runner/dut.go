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

	// DutAddr is the IP addres for DUT.
	DutAddr       = net.IPv4(0, 0, 0, 10)
	testbenchAddr = net.IPv4(0, 0, 0, 20)
)

// RegisterFlags defines flags and associates them with the package-level
// exported variables above. It should be called by tests in their init
// functions.
func RegisterFlags(fs *flag.FlagSet) {
	fs.BoolVar(&native, "native", false, "whether the test should be run natively")
	fs.StringVar(&testbenchBinary, "testbench_binary", "", "path to the testbench binary")
	fs.BoolVar(&tshark, "tshark", false, "use more verbose tshark in logs instead of tcpdump")
	flag.Var(&extraTestArgs, "extra_test_arg", "extra arguments to pass to the testbench")
	flag.BoolVar(&expectFailure, "expect_failure", false, "expect that the test will fail when run")
}

// CtrlPort is the port that posix_server listens on.
const CtrlPort = "40000"

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

// TestWithDUT runs a packetimpact test with the given information.
func TestWithDUT(ctx context.Context, t *testing.T, mkDevice func(*dockerutil.Container) DUT, containerAddr net.IP) {
	if testbenchBinary == "" {
		t.Fatal("--testbench_binary is missing")
	}
	dockerutil.EnsureSupportedDockerVersion()

	// Create the networks needed for the test. One control network is needed for
	// the gRPC control packets and one test network on which to transmit the test
	// packets.
	ctrlNet := dockerutil.NewNetwork(ctx, logger("ctrlNet"))
	testNet := dockerutil.NewNetwork(ctx, logger("testNet"))
	for _, dn := range []*dockerutil.Network{ctrlNet, testNet} {
		for {
			if err := createDockerNetwork(ctx, dn); err != nil {
				t.Log("creating docker network:", err)
				const wait = 100 * time.Millisecond
				t.Logf("sleeping %s and will try creating docker network again", wait)
				// This can fail if another docker network claimed the same IP so we'll
				// just try again.
				time.Sleep(wait)
				continue
			}
			break
		}
		dn := dn
		t.Cleanup(func() {
			if err := dn.Cleanup(ctx); err != nil {
				t.Errorf("unable to cleanup container %s: %s", dn.Name, err)
			}
		})
		// Sanity check.
		if inspect, err := dn.Inspect(ctx); err != nil {
			t.Fatalf("failed to inspect network %s: %v", dn.Name, err)
		} else if inspect.Name != dn.Name {
			t.Fatalf("name mismatch for network want: %s got: %s", dn.Name, inspect.Name)
		}
	}

	tmpDir, err := ioutil.TempDir("", "container-output")
	if err != nil {
		t.Fatal("creating temp dir:", err)
	}
	t.Cleanup(func() {
		if err := exec.Command("/bin/cp", "-r", tmpDir, os.Getenv("TEST_UNDECLARED_OUTPUTS_DIR")).Run(); err != nil {
			t.Errorf("unable to copy container output files: %s", err)
		}
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Errorf("failed to remove tmpDir %s: %s", tmpDir, err)
		}
	})

	const testOutputDir = "/tmp/testoutput"

	// Create the Docker container for the DUT.
	var dut *dockerutil.Container
	if native {
		dut = dockerutil.MakeNativeContainer(ctx, logger("dut"))
	} else {
		dut = dockerutil.MakeContainer(ctx, logger("dut"))
	}
	t.Cleanup(func() {
		dut.CleanUp(ctx)
	})

	runOpts := dockerutil.RunOpts{
		Image:  "packetimpact",
		CapAdd: []string{"NET_ADMIN"},
		Mounts: []mount.Mount{{
			Type:     mount.TypeBind,
			Source:   tmpDir,
			Target:   testOutputDir,
			ReadOnly: false,
		}},
	}

	// Add ctrlNet as eth1 and testNet as eth2.
	const testNetDev = "eth2"

	device := mkDevice(dut)
	remoteIPv6, remoteMAC, dutDeviceID := device.Prepare(ctx, t, runOpts, ctrlNet, testNet, containerAddr)

	// Create the Docker container for the testbench.
	testbench := dockerutil.MakeNativeContainer(ctx, logger("testbench"))

	tbb := path.Base(testbenchBinary)
	containerTestbenchBinary := filepath.Join("/packetimpact", tbb)
	testbench.CopyFiles(&runOpts, "/packetimpact", filepath.Join("test/packetimpact/tests", tbb))

	// Run tcpdump in the test bench unbuffered, without DNS resolution, just on
	// the interface with the test packets.
	snifferArgs := []string{
		"tcpdump",
		"-S", "-vvv", "-U", "-n",
		"-i", testNetDev,
		"-w", testOutputDir + "/dump.pcap",
	}
	snifferRegex := "tcpdump: listening.*\n"
	if tshark {
		// Run tshark in the test bench unbuffered, without DNS resolution, just on
		// the interface with the test packets.
		snifferArgs = []string{
			"tshark", "-V", "-l", "-n", "-i", testNetDev,
			"-o", "tcp.check_checksum:TRUE",
			"-o", "udp.check_checksum:TRUE",
		}
		snifferRegex = "Capturing on.*\n"
	}

	if err := StartContainer(
		ctx,
		runOpts,
		testbench,
		testbenchAddr,
		[]*dockerutil.Network{ctrlNet, testNet},
		snifferArgs...,
	); err != nil {
		t.Fatalf("failed to start docker container for testbench sniffer: %s", err)
	}
	// Kill so that it will flush output.
	t.Cleanup(func() {
		time.Sleep(1 * time.Second)
		testbench.Exec(ctx, dockerutil.ExecOpts{}, "killall", snifferArgs[0])
	})

	if _, err := testbench.WaitForOutput(ctx, snifferRegex, 60*time.Second); err != nil {
		t.Fatalf("sniffer on %s never listened: %s", dut.Name, err)
	}

	// When the Linux kernel receives a SYN-ACK for a SYN it didn't send, it
	// will respond with an RST. In most packetimpact tests, the SYN is sent
	// by the raw socket and the kernel knows nothing about the connection, this
	// behavior will break lots of TCP related packetimpact tests. To prevent
	// this, we can install the following iptables rules. The raw socket that
	// packetimpact tests use will still be able to see everything.
	for _, bin := range []string{"iptables", "ip6tables"} {
		if logs, err := testbench.Exec(ctx, dockerutil.ExecOpts{}, bin, "-A", "INPUT", "-i", testNetDev, "-p", "tcp", "-j", "DROP"); err != nil {
			t.Fatalf("unable to Exec %s on container %s: %s, logs from testbench:\n%s", bin, testbench.Name, err, logs)
		}
	}

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
		"--posix_server_ip", AddressInSubnet(DutAddr, *ctrlNet.Subnet).String(),
		"--posix_server_port", CtrlPort,
		"--remote_ipv4", AddressInSubnet(DutAddr, *testNet.Subnet).String(),
		"--local_ipv4", AddressInSubnet(testbenchAddr, *testNet.Subnet).String(),
		"--remote_ipv6", remoteIPv6.String(),
		"--remote_mac", remoteMAC.String(),
		"--remote_interface_id", fmt.Sprintf("%d", dutDeviceID),
		"--device", testNetDev,
		fmt.Sprintf("--native=%t", native),
	)
	testbenchLogs, err := testbench.Exec(ctx, dockerutil.ExecOpts{}, testArgs...)
	if (err != nil) != expectFailure {
		var dutLogs string
		if logs, err := device.Logs(ctx); err != nil {
			dutLogs = fmt.Sprintf("failed to fetch DUT logs: %s", err)
		} else {
			dutLogs = logs
		}

		t.Errorf(`test error: %v, expect failure: %t

%s

====== Begin of Testbench Logs ======

%s

====== End of Testbench Logs ======`,
			err, expectFailure, dutLogs, testbenchLogs)
	}
}

// DUT describes how to setup/teardown the dut for packetimpact tests.
type DUT interface {
	// Prepare prepares the dut, starts posix_server and returns the IPv6, MAC
	// address and the interface ID for the testNet on DUT.
	Prepare(ctx context.Context, t *testing.T, runOpts dockerutil.RunOpts, ctrlNet, testNet *dockerutil.Network, containerAddr net.IP) (net.IP, net.HardwareAddr, uint32)
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
func (dut *DockerDUT) Prepare(ctx context.Context, t *testing.T, runOpts dockerutil.RunOpts, ctrlNet, testNet *dockerutil.Network, containerAddr net.IP) (net.IP, net.HardwareAddr, uint32) {
	const containerPosixServerBinary = "/packetimpact/posix_server"
	dut.c.CopyFiles(&runOpts, "/packetimpact", "test/packetimpact/dut/posix_server")

	if err := StartContainer(
		ctx,
		runOpts,
		dut.c,
		containerAddr,
		[]*dockerutil.Network{ctrlNet, testNet},
		containerPosixServerBinary,
		"--ip=0.0.0.0",
		"--port="+CtrlPort,
	); err != nil {
		t.Fatalf("failed to start docker container for DUT: %s", err)
	}

	if _, err := dut.c.WaitForOutput(ctx, "Server listening.*\n", 60*time.Second); err != nil {
		t.Fatalf("%s on container %s never listened: %s", containerPosixServerBinary, dut.c.Name, err)
	}

	dutTestDevice, dutDeviceInfo, err := deviceByIP(ctx, dut.c, AddressInSubnet(containerAddr, *testNet.Subnet))
	if err != nil {
		t.Fatal(err)
	}

	remoteMAC := dutDeviceInfo.MAC
	remoteIPv6 := dutDeviceInfo.IPv6Addr
	// Netstack as DUT doesn't assign IPv6 addresses automatically so do it if
	// needed.
	if remoteIPv6 == nil {
		if _, err := dut.c.Exec(ctx, dockerutil.ExecOpts{}, "ip", "addr", "add", netdevs.MACToIP(remoteMAC).String(), "scope", "link", "dev", dutTestDevice); err != nil {
			t.Fatalf("unable to ip addr add on container %s: %s", dut.c.Name, err)
		}
		// Now try again, to make sure that it worked.
		_, dutDeviceInfo, err = deviceByIP(ctx, dut.c, AddressInSubnet(containerAddr, *testNet.Subnet))
		if err != nil {
			t.Fatal(err)
		}
		remoteIPv6 = dutDeviceInfo.IPv6Addr
		if remoteIPv6 == nil {
			t.Fatalf("unable to set IPv6 address on container %s", dut.c.Name)
		}
	}
	return remoteIPv6, dutDeviceInfo.MAC, dutDeviceInfo.ID
}

// Logs implements DUT.Logs.
func (dut *DockerDUT) Logs(ctx context.Context) (string, error) {
	logs, err := dut.c.Logs(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`====== Begin of DUT Logs ======

%s

====== End of DUT Logs ======`, logs), nil
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
// new address. The return address bits come from the subnet where the mask is 1
// and from the ip address where the mask is 0.
func AddressInSubnet(addr net.IP, subnet net.IPNet) net.IP {
	var octets []byte
	for i := 0; i < 4; i++ {
		octets = append(octets, (subnet.IP.To4()[i]&subnet.Mask[i])+(addr.To4()[i]&(^subnet.Mask[i])))
	}
	return net.IP(octets)
}

// deviceByIP finds a deviceInfo and device name from an IP address.
func deviceByIP(ctx context.Context, d *dockerutil.Container, ip net.IP) (string, netdevs.DeviceInfo, error) {
	out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "ip", "addr", "show")
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("listing devices on %s container: %w\n%s", d.Name, err, out)
	}
	devs, err := netdevs.ParseDevices(out)
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("parsing devices from %s container: %w\n%s", d.Name, err, out)
	}
	testDevice, deviceInfo, err := netdevs.FindDeviceByIP(ip, devs)
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("can't find deviceInfo for container %s: %w", d.Name, err)
	}
	return testDevice, deviceInfo, nil
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
func StartContainer(ctx context.Context, runOpts dockerutil.RunOpts, c *dockerutil.Container, containerAddr net.IP, ns []*dockerutil.Network, cmd ...string) error {
	conf, hostconf, netconf := c.ConfigsFrom(runOpts, cmd...)
	_ = netconf
	hostconf.AutoRemove = true
	hostconf.Sysctls = map[string]string{"net.ipv6.conf.all.disable_ipv6": "0"}

	if err := c.CreateFrom(ctx, conf, hostconf, nil); err != nil {
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
