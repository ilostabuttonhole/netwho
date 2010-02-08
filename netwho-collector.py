#!/usr/bin/env python
#
# Create a list of "who" each user is on a given network by sniffing their
# internet traffic. 

import datetime
import Queue
import sys
import optparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, load_module
from lib import storage
from preprocessors import http_gzip
from parsers import http_incoming
from parsers import dhcpv6_outgoing, irc_outgoing, http_outgoing, yahoo_outgoing, upnp_outgoing, zeroconf_outgoing

IP_CACHE = {}
STORAGE_PATH = '/tmp/netwho.db'
SAVE_QUEUE = Queue.Queue

load_module("p0f")

class IdentitySniffer(object):
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
    if keywords:
      self.keywords = keywords
    else:
      self.keywords = []

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

    self.storage = storage.SqliteStorage(STORAGE_PATH)
    if not self.filter:
      filters = set()
      for parser in self.parsers:
        for port in parser.DPORTS:
          filters.add('dst port %s' % port)
        for port in parser.SPORTS:
          filters.add('src port %s' % port)
      self.filter = ' or '.join(filters)
      self.seen = []

  def process_packet(self, pkt):
    payload = None
    handled_by_preproc = None
    
    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
#      print 'returning pkt, no IP stack'
      return

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
            return None

#          print 'sending %s to %s' % (pkt, parser)
          for result in parser.parse(pkt, payload):
            if parser.SPORTS:
              local_host = 'dst'
            else:
              local_host = 'src'

            if result:
              results.append((parser, result))

    hid = self.save_host(pkt, local_host)
    for result in results:
      iid = self.save_identity(hid, result)

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

if __name__ == '__main__':
  # For the time-being, we only accept pcap data as an argument.
  parser = optparse.OptionParser()
  parser.add_option('-r', '--file', dest='pcap_filename', default=None,
                    type='str', help='Path to pcap file to parse')
  parser.add_option('-i', '--interface', dest='interface', default=None,
                    type='str', help='Ethernet interface to use')
  parser.add_option('-k', '--keywords', dest='keywords', default=None,
                    type='str', help='Keywords to notify on if unmatched packet appears.')

  (options, args) = parser.parse_args()
  if args:
    filter = args[0]
  else:
    filter = None

  if options.keywords:
    keywords = options.keywords.split(',')
  else:
    keywords = None
  ids = IdentitySniffer(pcap_filename=options.pcap_filename, interface=options.interface, filter=filter,
                        keywords=keywords)
  ids.process_input()
