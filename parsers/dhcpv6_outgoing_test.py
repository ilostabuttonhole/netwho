#!/usr/bin/env python
# To change this template, choose Tools | Templates
# and open the template in the editor.

from scapy.all import sniff
import unittest
import irc_outgoing
from base_parser import Identity

class DhcpV6OutgoingTestCase(unittest.TestCase):
  def _load_testdata(self, file_path):
    packets = []
    def _add_packet(pkt):
      packets.append(pkt)

    path = '../testdata/dhcp/' + file_path
    sniff(prn=_add_packet, store=0, offline=path)
    return packets

  def test_connect(self):
    test_data = self._load_testdata('dhcpv6-outgoing-windows7.pcap')
    responses = list(irc_outgoing.IrcOutgoingParser().parse(test_data[0]))
    expected_nick = Identity('irc.freenode.net', 'connect', 'handle',
                             'helixblue', certainty=0.7)


if __name__ == '__main__':
    unittest.main()

