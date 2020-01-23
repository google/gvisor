# Lint as: python3
# Copyright 2020 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at //
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Base classes for packetimpact tests."""

import argparse
import itertools
import json
import os
import queue
import random
import socket
import threading

from scapy.all import AsyncSniffer
from scapy.all import conf
from scapy.all import Ether
from scapy.all import IP
from scapy.all import TCP

parser = argparse.ArgumentParser()
parser.add_argument(
    "--stub_ip",
    metavar="IP_ADDRESS",
    type=str,
    help="ip address for stub HTTP server",
    default="localhost")
parser.add_argument(
    "--stub_port",
    metavar="PORT",
    type=int,
    help="port for stub HTTP server",
    default=40000)
parser.add_argument(
    "--local_ip",
    metavar="IP_ADDRESS",
    type=str,
    help="local ip address for test packets")
parser.add_argument(
    "--remote_ip",
    metavar="IP_ADDRESS",
    type=str,
    help="remote ip address for test packets")
parser.add_argument(
    "--device", metavar="DEV", type=str, help="local device for test packets")
args = parser.parse_args()
_dut_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class DUTError(Exception):
  pass


class DUTMetaclass(type):
  """Metaclass to make __getattr__ for the DUT singleton."""

  def __getattr__(cls, name):

    def print_command(name, command_args, command_kwargs):
      """Print the command without a newline."""
      print(("DUT: " + name + "(" + ", ".join(
          itertools.chain(
              (repr(x) for x in command_args),
              (repr(k) + "=" + repr(v) for k, v in command_kwargs.items()))) +
             ")"),
            end="")

    def process_response(json_response):
      """Process the reponse into a return value or exception."""
      if json_response is None:
        return None
      if "exception" not in json_response:
        if "return" in json_response:
          return json_response["return"]
        return None
      outer_exception = DUTError(json_response["exception"])
      if "errno" not in json_response:
        raise outer_exception
      errno = json_response["errno"]
      inner_exception = socket.error(errno, os.strerror(errno))
      raise outer_exception from inner_exception

    def send_command(*command_args, **command_kwargs):
      """Send JSON command to DUT and return JSON response."""
      command_object = {
          "command": name,
          "args": command_args,
          "kwargs": command_kwargs,
      }
      print_command(name, command_args, command_kwargs)
      message = json.dumps(command_object, indent=2)
      _dut_socket.sendto(
          bytes(message, "utf-8"), (args.stub_ip, args.stub_port))
      json_response_text, _ = _dut_socket.recvfrom(1024)
      json_response = json.loads(json_response_text)
      print(" ===> ", end="")
      try:
        result = process_response(json_response)
        print(repr(result))
        return result
      except Exception as e:
        print(repr(e))
        raise

    return send_command


class DUT(metaclass=DUTMetaclass):

  def __init__(self):
    raise NotImplementedError()


def get_local_ip():
  return args.local_ip


def get_remote_ip():
  return args.remote_ip


def create_listener():
  """Command DUT to make a socket, bind to it, and listen.

  Returns:
    (listener socket file descriptor, new port number for listener)
  """
  s = DUT.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  DUT.bind(s, (get_remote_ip(), 0))
  _, port = DUT.getsockname(s)
  DUT.listen(s, 1)
  return s, port


class Connection(object):
  """Base class for the protocol connections."""

  def __init__(self, outer_connection=None):
    self.outer_connection = outer_connection
    self.send_socket = conf.L2socket(iface=args.device)
    self.sniff = None

  def __del__(self):
    self.stop_sniff()

  def start_sniff(self):
    self.frames = queue.Queue()
    sniffer_ready = threading.Semaphore(0)
    self.sniff = AsyncSniffer(
        iface=args.device,
        prn=self.frames.put,
        lfilter=self.sniff_filter(),
        started_callback=sniffer_ready.release)
    self.sniff.start()
    sniffer_ready.acquire()

  def stop_sniff(self):
    self.frames = None
    if self.sniff:
      self.sniff.stop()
      self.sniff = None

  def send(self, frame):
    """Sends a frame to the DUT."""
    self.send_socket.send(frame)

  def receive(self, timeout=1):
    """Receive a packet since the last send or None if timeout."""
    try:
      frame = self.frames.get(timeout=timeout)
    except queue.Empty:
      return None
    return self.get_header(frame)

  def sniff_filter(self):
    """Returns the filter result and the inner to be filtered."""
    return lambda x: True

  def get_payload(self, frame):
    """Return the payload inside this layer."""
    if self.outer_connection is None:
      return frame
    return self.get_header(frame).payload

  def get_header(self, frame):
    """Given a frame, get the header for the current Connection."""
    return self.outer_connection.get_payload(frame)

  def build_frame(self, **kwargs):
    """Returns a frame for sending."""
    header = self.build_header(**kwargs)
    outer_header = self.outer_connection.build_frame()
    if outer_header is not None:
      return outer_header / header
    return header


class DummyConnection(Connection):
  """This is the root for layers that have no enclosing layer, like Ether."""

  def get_payload(self, segment):
    """Returns the inner payload."""
    return segment

  def build_frame(self):
    return None


class EtherConnection(Connection):
  """Helper for sending and receiving IP packets with the DUT."""

  def __init__(self,
               local_mac=None,
               remote_mac=None,
               outer_connection=DummyConnection()):
    super().__init__()
    self.local_mac = local_mac
    self.remote_mac = remote_mac
    self.outer_connection = outer_connection

  def sniff_filter(self):
    """Returns a new filter for matching the Ether header of a frame."""

    def new_filter(frame):
      if not self.outer_connection.sniff_filter()(frame):
        return False
      ether = self.get_header(frame)
      return (isinstance(ether, Ether) and
              (self.remote_mac is None or ether.src == self.remote_mac) and
              (self.local_mac is None or ether.dst == self.local_mac))

    return new_filter

  def build_header(self, **kwargs):
    """Returns a header to be encapsulated for sending."""
    if self.local_mac is not None:
      kwargs["src"] = self.local_mac
    if self.remote_mac is not None:
      kwargs["dst"] = self.remote_mac
    return Ether(**kwargs)


class IPConnection(Connection):
  """Helper for sending and receiving IP packets with the DUT."""

  def __init__(self,
               local_ip=get_local_ip(),
               remote_ip=get_remote_ip(),
               outer_connection=EtherConnection()):
    super().__init__()
    self.local_ip = local_ip
    self.remote_ip = remote_ip
    self.outer_connection = outer_connection

  def sniff_filter(self):
    """Returns a filter for receiving IP packets."""

    def new_filter(frame):
      if not self.outer_connection.sniff_filter()(frame):
        return False
      ip_packet = self.get_header(frame)
      return (isinstance(ip_packet, IP) and
              (self.remote_ip is None or ip_packet.src == self.remote_ip) and
              (self.local_ip is None or ip_packet.dst == self.local_ip))

    return new_filter

  def build_header(self, **kwargs):
    """Returns a header for sending."""
    if self.local_ip is not None:
      kwargs["src"] = self.local_ip
    if self.remote_ip is not None:
      kwargs["dst"] = self.remote_ip
    return IP(**kwargs)


class TCPConnection(Connection):
  """Helper for sending and receiving TCP packets with the DUT."""

  def __init__(self,
               local_port=None,
               remote_port=None,
               seq=random.randint(0, 0xffffffff),
               check_ack=True,
               check_seq=True,
               outer_connection=IPConnection()):
    """Create a new TCP connection manager.

    Args:
      local_port: Local port number or None to assign automatically.
      remote_port: Remote port number of None to assign automatically.
      seq: Initial sequence number, default is random.
      check_ack: Raise an exception if the received ack number is incorrect.
      check_seq: Raise an exception if the received seq number is incorrect.
      outer_connection: Encapsulting Connection, default is IP.
    """
    super().__init__()
    self.local_port = local_port
    self.remote_port = remote_port
    self.outer_connection = outer_connection
    self.local_seq = seq
    self.remote_seq = None
    self.check_ack = check_ack
    self.check_seq = check_seq

  def _check_and_update_counters(self, tcp_segment):
    """Check seq and ack values and update future expectations.

    If self.check_ack is True, raise an exception if the incoming ACK packet
    doesn't acknowledge all sent data so far.

    If self.check_seq is True, raise an exception if the incoming sequence
    number doesn't match the most recently sent ACK number.

    Update the future expected sequence number.

    Args:
      tcp_segment: The TCP header to check.

    Raises:
      Exception: bad ack or bad sequence number.
    """
    if (self.check_ack and "A" in tcp_segment.flags and
        tcp_segment.ack != self.local_seq):
      raise Exception(f"bad ack: {tcp_segment.ack} != {self.local_seq}")

    if (self.check_seq and self.remote_seq is not None and
        self.remote_seq != tcp_segment.seq):
      raise Exception(f"bad seq: {tcp_segment.seq} != {self.remote_seq}")

    # Update information about the remote's sequence number.
    self.remote_seq = tcp_segment.seq + len(tcp_segment.payload)
    if set("SF") & set(tcp_segment.flags):
      self.remote_seq += 1
    self.remote_seq %= (2**32)

  def sniff_filter(self):
    """Returns a filter for receiving TCP packets."""

    def new_filter(frame):
      """Check if the incoming TCP segment matches this flow."""
      if not self.outer_connection.sniff_filter()(frame):
        return False
      tcp_segment = self.get_header(frame)
      if (not isinstance(tcp_segment, TCP) or
          (self.remote_port is not None and
           tcp_segment.sport != self.remote_port) or
          (self.local_port is not None and
           tcp_segment.dport != self.local_port)):
        return False
      self._check_and_update_counters(tcp_segment)
      return True

    return new_filter

  def send(self, frame):
    # Update the local sequence number to the next sequence number.  This must
    # be done before sending or else the values might not be ready in time for
    # the sniffer.
    self.local_seq += len(self.get_payload(frame))
    if set("SF") & set(self.get_header(frame).flags):
      self.local_seq += 1
    self.local_seq %= 2**32
    super().send(frame)

  def build_header(self, **kwargs):
    """Returns a TCP header for sending."""
    if self.local_port is not None and "sport" not in kwargs:
      kwargs["sport"] = self.local_port
    if self.remote_port is not None and "dport" not in kwargs:
      kwargs["dport"] = self.remote_port
    if self.local_seq is not None and "seq" not in kwargs:
      kwargs["seq"] = self.local_seq
    if self.remote_seq is not None and "ack" not in kwargs:
      kwargs["ack"] = self.remote_seq
    return TCP(**kwargs)

  def connect_to_dut(self):
    """Perform a 3-way handshake with the DUT.

    Raises:
      Exception: If a SYNCACK is not received.
    """
    self.send(self.build_frame(flags="S"))
    syn_ack = self.receive()
    if syn_ack.flags != "SA":
      raise Exception(f"bad flags: {syn_ack.flags} != \"SA\"")
    self.send(self.build_frame(flags="A"))

  def close_dut(self, fd):
    """Close socket on DUT, wait for FIN, and send ACK.

    Args:
      fd: socket file descriptor on the DUT.
    Raises:
      Exception: If a FINACK is not received.
    """
    DUT.close(fd)
    fin = self.receive()
    if fin.flags != "FA":
      raise Exception(f"bad flags: {fin.flags} != \"FA\"")
    self.send(self.build_frame(flags="A"))
