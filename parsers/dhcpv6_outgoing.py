import re
from scapy.all import UDP
from base_parser import BaseParser, Identity

class DhcpV6OutgoingParser(BaseParser):
  DPORTS = [547]
  PROTOCOL = 'DHCPv6'
  LAYER = UDP

  DOMAIN_RE = re.compile('\x00\x0d([\w-]+)\x00')
  def parse(self, pkt, payload):
    pkt.show()
    match = self.DOMAIN_RE.search(payload)
    if match:
      yield Identity(service='Machine', event='broadcast',
                     type='machine_name', value=match.group(1),
                     certainty=1)
