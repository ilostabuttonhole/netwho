#!/usr/bin/env python

import re
from base_parser import BaseParser, Identity

class HttpOutgoingParser(BaseParser):
  DPORTS = [80, 8000, 8080]
  PROTOCOL = 'HTTP'
  GMAIL_CHAT_RE = re.compile('\; gmailchat=(%s)\/')
  GRAVATAR_RE = re.compile('Cookie: gravatar=([\w]+)%7C')
  AGENT_RE = re.compile('User-Agent: (\w.*?)\r')

  def parse(self, pkt, payload):
    if not payload:
      yield None
    else:
      match = self.AGENT_RE.search(payload)
      if match:
        yield Identity(service='Browser', event='Request', type='browser_version',
                       value=match.group(1), certainty=0.5)
      # Wordpress
      if 'POST /wp-admin/' in payload:
        match = re.search('Host: ([\w\.]+)', payload)
        if match:
          yield Identity(service='Wordpress', event='Admin', type='url',
                         value=match.group(1), certainty=0.7)
      
      # Google Talk
      match = self.GMAIL_CHAT_RE.search(payload)
      if match:
        yield Identity(service='Google Talk', event='Update', type='login',
                       value=match.group(1), certainty=0.8)
        yield Identity(service='Google Account', event='Update', type='login',
                       value=match.group(1), certainty=0.5)

      # GMail
      elif 'GET /mail/' in payload:
        match = re.search('\&gausr=(%s)' % self.EMAIL_REGEXP, payload)
        if match:
          yield Identity(service='Google Account', event='Access', type='login',
                         value=match.group(1), certainty=0.8)
          yield Identity(service='Gmail', event='Access', type='login',
                         value=match.group(1), certainty=0.8)
          yield Identity(service='Gmail', event='Access', type='email',
                         value=match.group(1), certainty=0.5)

      # Gravatar
      match = self.GRAVATAR_RE.search(payload)
      if match:
        yield Identity(service='Gravatar', event='Access', type='login',
                       value=match.group(1), certainty=1)

      # brizzly.com
      if 'Brizzly%20%20%2F%20' in payload:
        match = re.search('Brizzly%20%20%2F%20(\w+)%0A', payload)
        if match:
          yield Identity(service='Brizzly', event='Access', type='login',
                         value=match.group(1), certainty=1)
      
      # Generic e-mail
      elif '&email=' in payload:
        match = re.search('&email=(%s)' % self.EMAIL_REGEXP, payload)
        if match:
          yield Identity(service='E-Mail', event='POST', type='email',
                         value=match.group(1), certainty=0.5)

