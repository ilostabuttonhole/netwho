#!/usr/bin/env python
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

"""Daemon to sniff traffic and dump device information to disk."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

import optparse
from lib import sniffer

if __name__ == '__main__':
  # For the time-being, we only accept pcap data as an argument.
  parser = optparse.OptionParser()
  parser.add_option('-r', '--file', dest='pcap_filename', default=None,
                    type='str', help='Path to pcap file to parse')
  parser.add_option('-i', '--interface', dest='interface', default=None,
                    type='str', help='Ethernet interface to use')
  parser.add_option('-k', '--keywords', dest='keywords', default=None,
                    type='str', help='Keywords to notify on if unmatched packet appears.')

  (options, args) = parser.parse_args()
  if args:
    filter = args[0]
  else:
    filter = None

  if options.keywords:
    keywords = options.keywords.split(',')
  else:
    keywords = None
  ids = sniffer.Sniffer(pcap_filename=options.pcap_filename, interface=options.interface, filter=filter,
                        keywords=keywords)
  ids.process_input()
