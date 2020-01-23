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

import socket
import sys
import time
import unittest

import test_runner
from test_runner import TCPConnection


class MyTest(unittest.TestCase):

  def test_with_linger2(self):
    self.linger2_test(True)

  def test_without_linger2(self):
    self.linger2_test(False)

  def linger2_test(self, set_linger2):
    """Tests DUT receiving an ACK after the connection is closed.

    If TCP_LINGER2 is set on the socket and the timer runs out, we expect an ACK
    after the connection to cause the DUT to respond with a RST.  If TCP_LINGER2
    is not set, the DUT will still be in FIN_WAIT to and not send RST.

    Args:
      set_linger2: True to setsockopt TCP_LINGER2 on the DUT.
    """
    listener, remote_port = test_runner.create_listener()
    new_tcp = TCPConnection(remote_port=remote_port)
    new_tcp.start_sniff()
    new_tcp.connect_to_dut()
    conn, _ = test_runner.DUT.accept(listener)
    if set_linger2:
      # set FIN_WAIT2 timeout to 1 second.
      test_runner.DUT.setsockopt(conn, socket.SOL_TCP, socket.TCP_LINGER2, 1)
    new_tcp.close_dut(conn)
    time.sleep(5)
    new_tcp.send(new_tcp.build_frame(flags="A"))
    if set_linger2:
      rst = new_tcp.receive()
      self.assertEqual(rst.flags, "R")
    else:
      # To make sure the reset doesn't show up, we'll wait 10 seconds
      rst = new_tcp.receive(timeout=10)
      self.assertIsNone(rst)


if __name__ == "__main__":
  unittest.main(argv=[sys.argv[0]])
