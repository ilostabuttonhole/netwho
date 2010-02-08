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

"""Callbacks to handle packet processing."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

from preprocessors import http_gzip
from parsers import http_incoming
from parsers import dhcpv6_outgoing, irc_outgoing, http_outgoing, yahoo_outgoing, upnp_outgoing, zeroconf_outgoing
from scapy.all import IP, IPv6, TCP, UDP

class Processor(object):
  
  def __init__(self):

    self.preprocessors = [
      http_gzip.GzipDecoder()
    ]

    self.parsers = [
      http_incoming.HttpIncomingParser(),
      dhcpv6_outgoing.DhcpV6OutgoingParser(),
      irc_outgoing.IrcOutgoingParser(),
      http_outgoing.HttpOutgoingParser(),
      upnp_outgoing.UniversalPlugAndPlayParser(),
      yahoo_outgoing.YahooInstantMessengerParser(),
      zeroconf_outgoing.ZeroconfOutgoingParser()
    ]  
  

  def process_packet(self, pkt):
    """Process a packet.
  
    Args:
      pkt: A scapy packet object
    
    Returns:
      device: A device profile.
    """
  
    payload = None
    handled_by_preproc = None
  
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
  #      print 'returning pkt, no IP stack'
      return (None, [])

    for preproc in self.preprocessors:
  #      print 'checking: %s' % preproc
      if pkt.haslayer(preproc.LAYER):
        if ((not preproc.DPORTS or (pkt[preproc.LAYER].dport in preproc.DPORTS)) and
            (not preproc.SPORTS or (pkt[preproc.LAYER].sport in preproc.SPORTS))):
          (handled_by_preproc, preproc_data) = preproc.parse(pkt)
          if handled_by_preproc:
            payload = preproc_data
            break

    # If something has it handled but is not ready yet, short-circuit.
    if handled_by_preproc and not payload:
  #      print 'returning pkt, preproc not completed.'
      return None

    results = []
    local_host = None

    for parser in self.parsers:
  #      print 'checking: %s' % parser
      if pkt.haslayer(parser.LAYER):
        if ((not parser.DPORTS or (pkt[parser.LAYER].dport in parser.DPORTS)) and
            (not parser.SPORTS or (pkt[parser.LAYER].sport in parser.SPORTS))):
          if not payload:
            payload = str(pkt[parser.LAYER].payload)

          if not payload and parser.PAYLOAD_REQUIRED:
            continue

          for result in parser.parse(pkt, payload):
            if parser.SPORTS:
              local_host = 'dst'
            else:
              local_host = 'src'

            if result:
              results.append((parser, result))

    return (local_host, results)
