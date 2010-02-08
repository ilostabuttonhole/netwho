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

"""UPNP Outgoing parser."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'


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
