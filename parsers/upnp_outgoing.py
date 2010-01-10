#!/usr/bin/env python

import re
from scapy.all import UDP
from base_parser import BaseParser, Identity

class UniversalPlugAndPlayParser(BaseParser):
  DPORTS = [1900]
  PROTOCOL = 'UPNP'
  LAYER = UDP

  SERVER_RE = re.compile('Server:(.*?)')
  def parse(self, pkt, payload):
    if payload:
      match = self.SERVER_RE.search(payload)
      if match:
        yield Identity(service='Machine', event='broadcast',
                       type='Operating System', value=match.group(1),
                       certainty=0.8)
