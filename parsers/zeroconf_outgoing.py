#!/usr/bin/env python

from scapy.all import UDP

import re
from base_parser import BaseParser, Identity

class ZeroconfOutgoingParser(BaseParser):
  DPORTS = [5353]
  PROTOCOL = 'MDNS'
  LAYER = UDP

  MODEL_RE = re.compile('model=([\w+,]+)')
  NAME_RE = re.compile('Machine Name=([\w\'\, ]+)')

  def parse(self, pkt, payload):
    if payload:
      match = self.MODEL_RE.search(payload)
      if match:
        yield Identity(service='Machine', event='broadcast', type='machine_type',
                       value=match.group(1), certainty=0.7)
      match = self.NAME_RE.search(payload)
      if match:
        yield Identity(service='Machine', event='broadcast', type='hostname',
                       value=match.group(1), certainty=0.7)
