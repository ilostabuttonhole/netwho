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

"""Command-line tool to display who is on your network."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'


from lib import storage
STORAGE_PATH = '/tmp/netwho.db'

s = storage.SqliteStorage(STORAGE_PATH)
identities = s.get_current_identities()
show_mac = None
last_mac = False


machines = {}

for identity in identities:
  mac_addr = identity['mac_addr']
  type = identity['type']
  if mac_addr not in machines:
    machines[mac_addr] = {'name': '', 'login': '', 'os': '', 'mach_name': ''}

  if not machines[mac_addr].get(type, None):
    machines[mac_addr][type] = identity['value']

for mac_addr in machines:
  if 'handle' in machines[mac_addr]:
    handle = machines[mac_addr]['handle']
  else:
    handle = machines[mac_addr]['login']
   
  if machines[mac_addr]['name']:
    user = machines[mac_addr]['name']
    if handle:
      user = "%s (%s)" % (user, handle)
  else:
    user = handle

  print '%-16.16s   %-10.10s   %-10.10s   %s' % ('mac address', 'host', 'os', 'user')
  print '-' * 79
  print '%-16.16s   %-10.10s   %-10.10s   %s' % (mac_addr, machines[mac_addr]['mach_name'],
                                                      machines[mac_addr]['os'], user)
