import os.path
import sqlite3

class SqliteStorage(object):
  def __init__(self, filename=None):
    if not os.path.exists(filename):
      create_tables = True
    else:
      create_tables = False
      
    self.conn = sqlite3.connect(filename)
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
    print (statement, args)
    self.cursor.execute(statement, args)
    self.conn.commit()
  
  # TODO(tstromberg): Add memoize here
  def _get_hostid_for_mac(self, mac_addr):
    print 'looking up: %s' % mac_addr
    self.save('SELECT id FROM hosts WHERE mac_addr=?', [mac_addr])
    for row in self.cursor:
      print 'mac %s is id %s' % (mac_addr, row[0])
      return row[0]

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

  def save_identity(self, hid, identity):
    self.save('INSERT INTO identities(host_id,service,event,type,value,certainty,'
                        'first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)',
                        (hid, identity.service, identity.event, identity.type, identity.value,
                         identity.certainty, identity.timestamp, identity.timestamp))
