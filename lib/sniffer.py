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

"""Module to handle sniffing data from an interface or pcap file."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'


from scapy.all import sniff, IP, IPv6, TCP, UDP, load_module
import datetime

# local
from . import storage
from . import processor

STORAGE_PATH = '/tmp/netwho.db'
load_module("p0f")


class Sniffer(object):
  def __init__(self, interface=None, pcap_filename=None, filter=None,
               keywords=None):
    """Create a IdentitySniffer
    
    Args:
      interface: interface name to sniff on
      pcap_filename: tcpdump output to process
      filter: pcap filter to use when capturing data
    """    
    self.interface = interface
    self.filter = filter
    self.pcap_filename = pcap_filename
    self.processor = processor.Processor()
    if keywords:
      self.keywords = keywords
    else:
      self.keywords = []

    self.storage = storage.SqliteStorage(STORAGE_PATH)
    if not self.filter:
      filters = set()
      for parser in self.processor.parsers:
        for port in parser.DPORTS:
          filters.add('dst port %s' % port)
        for port in parser.SPORTS:
          filters.add('src port %s' % port)
      self.filter = ' or '.join(filters)
      self.seen = []
    
  def process_packet(self, pkt):
    (host, results) = self.processor.process_packet(pkt)
    if results:
      print (host, results)
    
    if self.keywords:
      self.check_keywords(results, pkt, payload)

  def save_identity(self, hid, result):
    (parser, identity) = result
    return self.storage.save_identity(hid, identity)

  def save_host(self, pkt, local_host):
    if pkt.haslayer(IP):
      ip_type = IP
    elif pkt.haslayer(IPv6):
      ip_type = IPv6

    mac_addr = pkt['Ethernet'].fields[local_host]
    payload = pkt.payload
    ip = pkt.getlayer(ip_type).fields[local_host]
    if ip_type == IPv6:
      ipv6_addr = ip
      ipv4_addr = None
    else:
      ipv4_addr = ip
      ipv6_addr = None

    hid = self.storage.update_host(mac_addr, ipv4_addr, ipv6_addr,
                                   datetime.datetime.fromtimestamp(pkt.time))
    return hid

  def check_keywords(self, results, pkt, payload):
    if payload and self.keywords:
      for keyword in self.keywords:
        if keyword.lower() in payload.lower():
          caught = False
          for result in results:
            if keyword in result[-1].value:
              caught = True
              break

          if not caught:
            print '*' * 72
            print "- Found %s in: %s" % (keyword, payload)
            print pkt.summary()
            print results
            print '-' * 72


  def process_input(self):
    """Call this when you are ready for IdentitySniffer to do something."""
    print "filter: %s" % self.filter
    if self.interface:
      sniff(prn=self.process_packet, store=0, filter=self.filter, iface=self.interface)
    elif self.pcap_filename:
      sniff(prn=self.process_packet, store=0, offline=self.pcap_filename)
    else:
      sniff(prn=self.process_packet, store=0, filter=self.filter)

