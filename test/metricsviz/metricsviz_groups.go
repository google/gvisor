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

package metricsviz

// GroupName is the name of a group of metrics.
type GroupName string

// Groups maps metrics which are in the same named group.
// If more than one metric in a group is in the profiled data, it will
// be shown on the same graph.
// A metric may be in multiple groups.
var Groups = map[GroupName][]MetricName{
	"Network packets": {
		"/netstack/dropped_packets",
		"/netstack/nic/malformed_l4_received_packets",
		"/netstack/nic/tx/packets",
		"/netstack/nic/tx_packets_dropped_no_buffer_space",
		"/netstack/nic/rx/packets",
		"/netstack/nic/disabled_rx/packets",
	},
	"Network throughput": {
		"/netstack/nic/tx/bytes",
		"/netstack/nic/rx/bytes",
		"/netstack/nic/disabled_rx/bytes",
	},
	"IP packets": {
		"/netstack/ip/packets_received",
		"/netstack/ip/disabled_packets_received",
		"/netstack/ip/invalid_addresses_received",
		"/netstack/ip/invalid_source_addresses_received",
		"/netstack/ip/packets_delivered",
		"/netstack/ip/packets_sent",
		"/netstack/ip/outgoing_packet_errors",
		"/netstack/ip/malformed_packets_received",
		"/netstack/ip/malformed_fragments_received",
		"/netstack/ip/iptables/prerouting_dropped",
		"/netstack/ip/iptables/input_dropped",
		"/netstack/ip/iptables/output_dropped",
		"/netstack/ip/options/timestamp_received",
		"/netstack/ip/options/record_route_received",
		"/netstack/ip/options/router_alert_received",
		"/netstack/ip/options/unknown_received",
	},
}
