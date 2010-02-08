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

"""Module to dump device identification to disk."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

import os.path
import sqlite3

class SqliteStorage(object):
  def __init__(self, filename=None):
    if not os.path.exists(filename):
      create_tables = True
    else:
      create_tables = False
      
    self.conn = sqlite3.connect(filename)
    self.conn.row_factory = sqlite3.Row      
    self.cursor = self.conn.cursor()
    if create_tables:
      self.create_tables()
    self.host_ids = {}
    self.identity_ids = {}

  def create_tables(self):
    self.cursor.execute("""
      CREATE TABLE hosts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac_addr VARCHAR(18),
        ipv4_addr VARCHAR(16),
        ipv6_addr VARCHAR(42),
        first_seen TIMESTAMP(8),
        last_seen TIMESTAMP(8),
        CONSTRAINT mac_unique UNIQUE(mac_addr)
      );
    """)
    
    self.cursor.execute("""
      CREATE TABLE identities(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INT REFERENCES hosts(id),
        service VARCHAR(32),
        event VARCHAR(32),
        type VARCHAR(32),
        value VARCHAR(32),
        certainty DECIMAL(2,2),
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        CONSTRAINT id_unique UNIQUE (service,event,type,value)
      );
    """)
    self.conn.commit()
    
  def save(self, statement, args=None):
    self.query(statement, args)
    self.conn.commit()
  
  def query(self, statement, args=None):
    if args:
      self.cursor.execute(statement, args)
    else:
      self.cursor.execute(statement)
      

  
  # TODO(tstromberg): Add memoize here
  def _get_hostid_for_mac(self, mac_addr):
    self.cursor.execute('SELECT id FROM hosts WHERE mac_addr=?', [mac_addr])
    for row in self.cursor:
#      print 'mac %s is id %s' % (mac_addr, row['id'])
      return row['id']

  def update_host(self, mac_addr, ipv4_addr, ipv6_addr, ts):
    hid = self._get_hostid_for_mac(mac_addr)
    if hid:
      self.save('UPDATE hosts SET last_seen=? WHERE id=?', (ts, hid))
    else:
      self.save('INSERT INTO hosts(mac_addr, ipv4_addr, ipv6_addr, first_seen, last_seen)'
                          ' VALUES (?,?,?,?,?)', (mac_addr, ipv4_addr, ipv6_addr, ts, ts))
      hid = self._get_hostid_for_mac(mac_addr)
    return hid

  def _get_identity(self, identity):
    self.cursor.execute('SELECT id FROM identities WHERE service=? AND event=? AND type=? AND value=?',
                        (identity.service, identity.event, identity.type, identity.value))
    for row in self.cursor:
      return row[0]

  def get_current_identities(self):
    self.query("""
      SELECT * FROM (
        SELECT mac_addr, ipv6_addr, ipv4_addr, service, type, value
        FROM identities
        JOIN hosts ON identities.host_id = hosts.id
        ORDER BY mac_addr, identities.certainty DESC, identities.last_seen DESC
      )
      AS subselect GROUP BY 1, 2, 3, 4;
    """)
    return self.cursor.fetchall()

  def save_identity(self, hid, identity):
    try:
      self.save('INSERT INTO identities(host_id,service,event,type,value,certainty,'
                'first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)',
                (hid, identity.service, identity.event, identity.type, identity.value,
                 identity.certainty, identity.timestamp, identity.timestamp))
    except sqlite3.IntegrityError:
      pass
#      print "%s already in db" % identity

