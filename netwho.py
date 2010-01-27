#!/usr/bin/env python
#
# Read the netwho database

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
