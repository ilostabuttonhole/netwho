# To change this template, choose Tools | Templates
# and open the template in the editor.

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


      