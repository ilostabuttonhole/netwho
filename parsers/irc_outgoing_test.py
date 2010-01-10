#!/usr/bin/env python
# To change this template, choose Tools | Templates
# and open the template in the editor.

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

