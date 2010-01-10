# To change this template, choose Tools | Templates
# and open the template in the editor.

__author__="tstromberg"

import re

from base_parser import BaseParser, Identity

class IrcOutgoingParser(BaseParser):
  DPORTS = [6667, 6668, 6669, 8001]
  PROTOCOL = 'IRC'

  CONNECT_RE = re.compile('NICK (\w+)\r\nUSER (\w+) .*? ([\w\.]+) :(.*?)\r\n')
  TOPIC_RE = re.compile(':([\w\.]+) 332 (\w+) (\#\w+) :')

  def parse(self, pkt, payload):

    if not payload:
      yield None
    else:
      match = self.CONNECT_RE.search(payload)
      if match:
        (nick, username, server, full_name) = match.groups()
        yield Identity(service=server, event='connect', type='handle',
                       value=nick, certainty=0.7)
        yield Identity(service=server, event='connect', type='name',
                       value=full_name, certainty=0.3)
        yield Identity(service=server, event='connect', type='username',
                       value=username, certainty=0.25)

      match = self.TOPIC_RE.search(payload)
      if match:
        (server, nick, channel) = match.groups()
        yield Identity(service='%s: %s' % (server, channel), event='topic',
                       type='handle', value=nick, certainty=1)

