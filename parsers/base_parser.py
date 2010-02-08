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

"""Helper methods for parsers."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

from scapy.all import TCP

class BaseParser(object):
  DPORTS = []
  SPORTS = []
  PROTOCOL = None
  LAYER = TCP
  PAYLOAD_REQUIRED = True

  EMAIL_REGEXP = '[\w].*?[\@\%][\w\.]+'

  def parse(self):
    return ValueError('undefined.')

class Identity(object):
  def __init__(self, service=None, event=None, type=None, value=None, certainty=None,
               timestamp=None):
    self.service = service
    self.type = type
    self.event = event
    self.value = value
    self.timestamp = timestamp
    if certainty:
      self.certainty = certainty
    else:
      self.certainty = 0.75

    self.attrs = ('service', 'event', 'type', 'value', 'certainty')

  def __repr__(self):
    attrs = []
    for attr in self.attrs:
      attrs.append("%s='%s'" % (attr, getattr(self, attr)))
    return 'Identity(%s)' % ', '.join(attrs)

  def __eq__(self, other):
    for attr in self.attrs:
      if getattr(self, attr) != getattr(other, attr):
        return False
    return True
      
  def __ne__(self, other):
    for attr in self.attrs:
      if getattr(self, attr) != getattr(other, attr):
        return True
    return False


      