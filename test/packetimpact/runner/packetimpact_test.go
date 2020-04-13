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

// The runner starts docker containers and networking for a packetimpact test.
package packetimpact_test

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kr/pty"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
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
	dutPlatform       = flag.String("dut_platform", "", "either \"linux\" or \"netstack\"")
	posixServerBinary = flag.String("posix_server_binary", "", "path to the posix server binary")
	testbenchBinary   = flag.String("testbench_binary", "", "path to the testbench binary")
	tshark            = flag.Bool("tshark", false, "use more verbose tshark in logs instead of tcpdump")
	extraTestArgs     = stringList{}
	expectFailure     = flag.Bool("expect_failure", false, "expect that the test will fail when run")

	dutAddr       = net.IPv4(0, 0, 0, 10)
	testbenchAddr = net.IPv4(0, 0, 0, 20)
	ctrlPort      = strconv.Itoa(40000)
)

// Logger implements testutil.Logger.
type logger string

// Name implements testutil.Logger.Name.
func (l logger) Name() string {
	return string(l)
}

// Logf implements testutil.Logger.Logf.
func (l logger) Logf(format string, args ...interface{}) {
	lines := strings.Split(fmt.Sprintf(format, args...), "\n")
	if len(lines) > 0 {
		log.Printf("%s: %s", l, lines[0])
	}
	if len(lines) > 1 {
		for _, line := range lines[1:] {
			log.Printf("%*s  %s", len(l), "", line)
		}
	}
}

func TestOne(t *testing.T) {
	flag.Var(&extraTestArgs, "extra_test_arg", "extra arguments to pass to the testbench")
	flag.Parse()
	if *dutPlatform != "linux" && *dutPlatform != "netstack" {
		t.Fatalf("--dut_platform should be either linux or netstack")
	}
	if *posixServerBinary == "" {
		t.Fatalf("--posix_server_binary is missing")
	}
	if *testbenchBinary == "" {
		t.Fatalf("--testbench_binary is missing")
	}
	if *dutPlatform == "netstack" {
		if _, err := dockerutil.RuntimePath(); err != nil {
			t.Fatalf("--runtime is missing or invalid with --dut_platform=netstack")
		}
	}
	dockerutil.EnsureSupportedDockerVersion()

	// Create the networks needed for the test. One control network is needed for
	// the gRPC control packets and one test network on which to transmit the test
	// packets.
	ctrlNet := dockerutil.NewDockerNetwork(logger("ctrlNet"))
	testNet := dockerutil.NewDockerNetwork(logger("testNet"))
	for _, dn := range []*dockerutil.DockerNetwork{ctrlNet, testNet} {
		for err := createDockerNetwork(dn); err != nil; err = createDockerNetwork(dn) {
			// This can fail if another docker network claimed the same IP so we'll
			// just try again.
			time.Sleep(100 * time.Millisecond)
		}
		defer func(dn *dockerutil.DockerNetwork) {
			if err := dn.Cleanup(); err != nil {
				t.Errorf("unable to cleanup %v: %s", dn, err)
			}
		}(dn)
	}

	// Create the Docker container for the DUT.
	dut := dockerutil.MakeDocker(logger("dut"))
	if *dutPlatform == "linux" {
		dut.Runtime = ""
	}

	// Create the Docker container for the testbench.
	testbench := dockerutil.MakeDocker(logger("testbench"))
	testbench.Runtime = "" // The testbench always runs on Linux.

	// Connect each container to each network.
	for _, d := range []struct {
		*dockerutil.Docker
		ipSuffix net.IP
	}{
		{dut, dutAddr},
		{testbench, testbenchAddr},
	} {
		// Create the container.
		if err := d.Docker.Create(dockerutil.RunOpts{Image: "packetimpact", CapAdd: []string{"NET_ADMIN"}, Extra: []string{"--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--rm", "--stop-timeout", "60", "-it"}}); err != nil {
			t.Fatalf("unable to create %v: %s", d.Docker, err)
		}
		defer d.CleanUp()
		for _, dn := range []*dockerutil.DockerNetwork{ctrlNet, testNet} {
			ip := addressInSubnet(d.ipSuffix, *dn.Subnet)
			// Connect to the network with the specified IP address.
			if err := dn.Connect(d.Docker, "--ip", ip.String()); err != nil {
				t.Fatalf("unable to connect %v to network %v: %s", d.Docker, dn, err)
			}
		}
		if err := d.Docker.Start(); err != nil {
			t.Fatalf("unable to start %v: %s", d.Docker, err)
		}
	}

	containerPosixServerBinary := "/" + path.Base(*posixServerBinary)
	// TODO(eyalsoha): Convert the below line to dut.Copy(...)
	if err := testutil.Command(logger("cp"), "docker", "cp", "-L", *posixServerBinary, dut.Name+":"+containerPosixServerBinary).Run(); err != nil {
		t.Fatalf("can't copy posix_server to dut: %s", err)
	}
	containerTestbenchBinary := "/" + path.Base(*testbenchBinary)
	// TODO(eyalsoha): Convert the below line to testbench.Copy(...)
	if err := testutil.Command(logger("cp"), "docker", "cp", "-L", *testbenchBinary, testbench.Name+":"+containerTestbenchBinary).Run(); err != nil {
		t.Fatalf("can't copy test to testbench: %s", err)
	}

	ip := addressInSubnet(dutAddr, *ctrlNet.Subnet)
	posixServerLogger := logger("posix_server")
	_, ptmx, err := execUntil("Server listening.*\n", posixServerLogger, "docker", "exec", "-t", dut.Name, containerPosixServerBinary, "--ip="+ip.String(), "--port="+ctrlPort)
	if err != nil {
		t.Fatalf("unable to execUntil %s on %v: %s", containerPosixServerBinary, dut, err)
	}
	// TODO(eyalsoha): Handle the error from copyIO.
	go copyIO(posixServerLogger.Logf, ptmx)
	defer func(ptmx *os.File) {
		if err := ptmx.Close(); err != nil {
			t.Errorf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)

	dutTestDevice, dutDeviceInfo, err := deviceByIP(dut, addressInSubnet(dutAddr, *testNet.Subnet))
	if err != nil {
		t.Fatalf("can't find deviceInfo for on %v: %s", dut, err)
	}
	testbenchTestDevice, testbenchDeviceInfo, err := deviceByIP(testbench, addressInSubnet(testbenchAddr, *testNet.Subnet))
	if err != nil {
		t.Fatalf("can't find deviceInfo for on %v: %s", testbench, err)
	}

	// Because the Linux kernel receives the SYN-ACK but didn't send the SYN it
	// will issue a RST. To prevent this IPtables can be used to filter out all
	// incoming packets. The raw socket that packetimpact tests use will still see
	// everything.
	if _, err := testbench.Exec(dockerutil.RunOpts{}, "iptables", "-A", "INPUT", "-i", testbenchTestDevice, "-j", "DROP"); err != nil {
		t.Fatalf("unable to Exec iptables on %v: %s", testbench, err)
	}

	remoteMAC := dutDeviceInfo.mac
	localMAC := testbenchDeviceInfo.mac
	remoteIPv6 := dutDeviceInfo.ipv6Addr
	localIPv6 := testbenchDeviceInfo.ipv6Addr
	// Netstack as DUT doesn't assign IPv6 addresses automatically so do it if
	// needed.
	if remoteIPv6 == nil {
		dut.Exec(dockerutil.RunOpts{}, "ip", "addr", "add", macToIP(remoteMAC).String(), "scope", "link", "dev", dutTestDevice)
		// Now try again, to make sure that it worked.
		_, dutDeviceInfo, err = deviceByIP(dut, addressInSubnet(dutAddr, *testNet.Subnet))
		if err != nil {
			t.Fatalf("can't find deviceInfo for on %v: %s", dut, err)
		}
		remoteIPv6 = dutDeviceInfo.ipv6Addr
		if remoteIPv6 == nil {
			t.Fatalf("unable to set IPv6 address on DUT")
		}
	}

	// Run tcpdump in the test bench unbuffered, without dns resolution, just on
	// the interface with the test packets.
	snifferArgs := []string{
		"tcpdump", "-S", "-vvv", "-U", "-n", "-i", testbenchTestDevice,
		"net", testNet.Subnet.String(), "or",
		"host", localIPv6.String(), "or",
		"host", remoteIPv6.String(),
	}
	snifferRegex := "tcpdump: listening.*\n"
	if *tshark {
		// Run tshark in the test bench unbuffered, without dns resolution, just on
		// the interface with the test packets.udp_recv_multicast_linux_test
		snifferArgs = []string{
			"tshark", "-V", "-l", "-n", "-i", testbenchTestDevice,
			"-o", "tcp.check_checksum:TRUE",
			"-o", "udp.check_checksum:TRUE",
			"net", testNet.Subnet.String(), "or",
			"host", localIPv6.String(), "or",
			"host", remoteIPv6.String(),
		}
		snifferRegex = "Capturing on.*\n"
	}
	snifferLogger := logger(snifferArgs[0])
	_, ptmx, err = execUntil(snifferRegex, snifferLogger, append([]string{"docker", "exec", "-t", testbench.Name}, snifferArgs...)...)
	if err != nil {
		t.Fatalf("unable to run %s on %v: %s", snifferArgs[0], testbench, err)
	}
	// TODO(eyalsoha): Handle the error from copyIO.
	go copyIO(snifferLogger.Logf, ptmx)
	defer func(ptmx *os.File) {
		if err := ptmx.Close(); err != nil {
			t.Errorf("unable to close %v: %s", ptmx, err)
		}
	}(ptmx)
	// Kill so that it will flush output.
	defer testbench.Exec(dockerutil.RunOpts{}, "killall", snifferArgs[0])

	// Start a packetimpact test on the test bench. The packetimpact test sends
	// and receives packets and also sends POSIX socket commands to the
	// posix_server to be executed on the DUT.
	testArgs := []string{containerTestbenchBinary}
	testArgs = append(testArgs, extraTestArgs...)
	testArgs = append(testArgs,
		"--posix_server_ip", addressInSubnet(dutAddr, *ctrlNet.Subnet).String(),
		"--posix_server_port", ctrlPort,
		"--remote_ipv4", addressInSubnet(dutAddr, *testNet.Subnet).String(),
		"--local_ipv4", addressInSubnet(testbenchAddr, *testNet.Subnet).String(),
		"--remote_ipv6", remoteIPv6.String(),
		"--local_ipv6", localIPv6.String(),
		"--remote_mac", remoteMAC.String(),
		"--local_mac", localMAC.String(),
		"--device", testbenchTestDevice,
	)
	unittestLogger := logger("unittest")
	cmd, ptmx, err := execUntil("", unittestLogger, append([]string{"docker", "exec", "-t", testbench.Name}, testArgs...)...)
	if err != nil {
		t.Fatalf("unable to exec %s on %v: %s", testArgs, testbench, err)
	}
	// TODO(eyalsoha): Handle the error from copyIO.
	go copyIO(unittestLogger.Logf, ptmx)

	err = cmd.Wait() // No need to ptmx.Close() because we call cmd.Wait() instead.
	if !*expectFailure && err != nil {
		t.Fatalf("test failed with exit code %d: %s", cmd.ProcessState.ExitCode(), err)
	}
	if *expectFailure && err == nil {
		t.Fatalf("test failure expected but the test succeeded, enable the test and mark the corresponding bug as fixed")
	}
}

// addressInSubnet combines the subnet provided with the address and returns a
// new address. The return address bits come from the subnet where the mask is 1
// and from the ip address where the mask is 0.
func addressInSubnet(addr net.IP, subnet net.IPNet) net.IP {
	var octets []byte
	for i := 0; i < 4; i++ {
		octets = append(octets, (subnet.IP.To4()[i]&subnet.Mask[i])+(addr.To4()[i]&(^subnet.Mask[i])))
	}
	return net.IP(octets)
}

// makeDockerNetwork makes a randomly-named network that will start with the
// namePrefix. The network will be a random /24 subnet.
func createDockerNetwork(n *dockerutil.DockerNetwork) error {
	randSource := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(randSource)
	// Class C, 192.0.0.0 to 223.255.255.255, transitionally has mask 24.
	ip := net.IPv4(byte(r1.Intn(224-192)+192), byte(r1.Intn(256)), byte(r1.Intn(256)), 0)
	n.Subnet = &net.IPNet{
		IP:   ip,
		Mask: ip.DefaultMask(),
	}
	return n.Create()
}

// copyIOUntil copies from reader to writer. It buffers by line and uses f to
// display. When the input matches the regex, return.
func copyIOUntil(regex string, f func(format string, args ...interface{}), r io.Reader) error {
	var bb bytes.Buffer
	var b [1]byte
	for {
		if _, err := r.Read(b[:]); err != nil {
			return err
		}
		if _, err := bb.Write(b[:]); err != nil {
			return err
		}
		if bytes.Equal(b[:], []byte("\n")) {
			f("%s", string(bb.Bytes()[:bb.Len()-1]))
			found, err := regexp.Match(regex, bb.Bytes())
			if err != nil {
				return err
			}
			if found {
				break
			}
			bb.Truncate(0)
		}
	}
	return nil
}

// copyIO copies from reader to writer. It buffers by line and uses f to
// display.
func copyIO(f func(format string, args ...interface{}), r io.Reader) error {
	var bb bytes.Buffer
	var b [1]byte
	for {
		if _, err := r.Read(b[:]); err != nil {
			return err
		}
		if _, err := bb.Write(b[:]); err != nil {
			return err
		}
		if bytes.Equal(b[:], []byte("\n")) {
			f("%s", string(bb.Bytes()[:bb.Len()-1]))
			bb.Truncate(0)
		}
	}
}

// execUntil runs a docker command on a container, outputting lines to the
// logger. It returns as soon as the output matches the regex provided.
func execUntil(regex string, l testutil.Logger, args ...string) (*testutil.Cmd, *os.File, error) {
	// TODO(eyalsoha): Convert the below line to a method on *dockerutil.Docker.
	cmd := testutil.Command(l, args...)
	ptmx, err := pty.Start(cmd.Cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("error executing docker %v with a pty: %v", cmd, err)
	}
	if err := copyIOUntil(regex, l.Logf, ptmx); err != nil {
		return nil, nil, err
	}
	return cmd, ptmx, nil
}

type deviceInfo struct {
	mac      net.HardwareAddr
	ipv4Addr net.IP
	ipv4Net  *net.IPNet
	ipv6Addr net.IP
	ipv6Net  *net.IPNet
}

var deviceLine = regexp.MustCompile(`^\s*\d+: (\w+)`)
var linkLine = regexp.MustCompile(`^\s*link/\w+ ([0-9a-fA-F:]+)`)
var inetLine = regexp.MustCompile(`^\s*inet ([0-9./]+)`)
var inet6Line = regexp.MustCompile(`^\s*inet6 ([0-9a-fA-Z:/]+)`)

// listDevices returns a map from device name to information about the device.
func listDevices(d *dockerutil.Docker) (map[string]deviceInfo, error) {
	out, err := d.Exec(dockerutil.RunOpts{}, "ip", "addr", "show")
	if err != nil {
		return nil, err
	}
	var currentDevice string
	var currentInfo deviceInfo
	deviceInfos := make(map[string]deviceInfo)
	for _, line := range strings.Split(out, "\n") {
		if m := deviceLine.FindStringSubmatch(line); m != nil {
			if currentDevice != "" {
				deviceInfos[currentDevice] = currentInfo
			}
			currentInfo = deviceInfo{}
			currentDevice = m[1]
		} else if m := linkLine.FindStringSubmatch(line); m != nil {
			mac, err := net.ParseMAC(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.mac = mac
		} else if m := inetLine.FindStringSubmatch(line); m != nil {
			ipv4Addr, ipv4Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.ipv4Addr = ipv4Addr
			currentInfo.ipv4Net = ipv4Net
		} else if m := inet6Line.FindStringSubmatch(line); m != nil {
			ipv6Addr, ipv6Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.ipv6Addr = ipv6Addr
			currentInfo.ipv6Net = ipv6Net
		}
	}
	if currentDevice != "" {
		deviceInfos[currentDevice] = currentInfo
	}
	return deviceInfos, nil
}

// Convert the MAC address to an IPv6 link local address as described in RFC
// 4291 page 20: https://tools.ietf.org/html/rfc4291#page-20
func macToIP(mac net.HardwareAddr) net.IP {
	// Split the octets of the MAC into an array of strings.
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

// deviceByIP finds a deviceInfo and device name from an IP address.
func deviceByIP(d *dockerutil.Docker, ip net.IP) (string, deviceInfo, error) {
	testbenchDeviceInfos, err := listDevices(d)
	if err != nil {
		return "", deviceInfo{}, fmt.Errorf("unable to listDevices on %v: %w", d, err)
	}
	for dev, info := range testbenchDeviceInfos {
		if info.ipv4Addr.Equal(ip) {
			return dev, info, nil
		}
	}
	return "", deviceInfo{}, fmt.Errorf("can't find %v on %vtestbench", ip, d)
}
