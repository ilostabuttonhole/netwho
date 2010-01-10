#!/usr/bin/env python

from scapy.all import UDP

import re
from base_parser import BaseParser, Identity

class YahooInstantMessengerParser(BaseParser):
  DPORTS = [5150]
  PROTOCOL = 'YIM'
  LAYER = UDP

  PING_RE = re.compile('YMSG.*\xc0\x80(.*)\xc0\x80')

  def parse(self, pkt, payload):
    if payload:
      match = self.PING_RE.search(payload)
      if match:
        yield Identity(service='Yahoo Instant Messenger', event='broadcast',
                       type='login', value=match.group(1), certainty=1.0)
