# Copyright 2010 The NetWho Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for IRC outgoing parser."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

from scapy.all import sniff
import unittest
import irc_outgoing
from base_parser import Identity

class IrcOutgoingTestCase(unittest.TestCase):
  def _load_testdata(self, file_path):
    packets = []
    def _add_packet(pkt):
      packets.append(pkt)

    path = '../testdata/irc/' + file_path
    sniff(prn=_add_packet, store=0, offline=path)
    return packets

  def test_connect(self):
    test_data = self._load_testdata('connect.pcap')
    responses = list(irc_outgoing.IrcOutgoingParser().parse(test_data[0]))
    expected_nick = Identity('irc.freenode.net', 'connect', 'handle',
                             'helixblue', certainty=0.7)
    self.assertEquals(responses[0], expected_nick)
    self.assertEquals(responses[1].value, 'thomas')
    self.assertEquals(responses[1].type, 'name')

    self.assertEquals(responses[2].value, 'tstromberg')
    self.assertEquals(responses[2].type, 'username')

  def test_channel_join(self):
    test_data = self._load_testdata('incoming_channel_join.pcap')
    responses = list(irc_outgoing.IrcOutgoing().parse(test_data[0]))
    expected_nick = Identity('zelazny.freenode.net: #hsbxl', 'topic', 'handle',
                             'helixblue', certainty=1)
    self.assertEquals(responses[0], expected_nick)


if __name__ == '__main__':
    unittest.main()

