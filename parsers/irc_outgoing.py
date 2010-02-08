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

"""IRC outgoing parser."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'


import re

from base_parser import BaseParser, Identity

class IrcOutgoingParser(BaseParser):
  DPORTS = [6667, 6668, 6669, 8001]
  PROTOCOL = 'IRC'

  CONNECT_RE = re.compile('NICK (\w+)\r\nUSER (\w+) .*? ([\w\.]+) :(.*?)\r\n')
  TOPIC_RE = re.compile(':([\w\.]+) 332 (\w+) (\#\w+) :')

  def parse(self, pkt, payload):
    if not payload:
      print 'none'
      yield None
    else:
      match = self.CONNECT_RE.search(payload)
      if match:
        print match
        (nick, username, server, full_name) = match.groups()
        print match.groups()
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

