import sqlite3

class SqliteStorage(object):
  def __init__(self, filename=None):
    self.conn = sqlite3.connect(filename)
    self.cursor = self.conn.cursor()
    self.host_ids = {}
    self.identity_ids = {}

  def create_tables(self):
    sql = """
      CREATE TABLE hosts(
        id INT AUTO_INCREMENT PRIMARY KEY,
        mac_addr VARCHAR(12),
        ipv4_address VARCHAR(15),
        ipv6_address VARCHAR(40),
        first_seen TIMESTAMP(8),
        last_seen TIMESTAMP(8),
        CONSTRAINT mac_unique UNIQUE(mac_addr)
      );

      CREATE TABLE identities(
        id INT AUTO_INCREMENT PRIMARY KEY,
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
    """
    self.cursor.execute(sql)

  # TODO(tstromberg): Add memoize here
  def _get_hostid_for_mac(self, mac_addr):
    self.cursor.execute("SELECT id FROM hosts WHERE mac_addr=?", mac_addr)
    for row in self.cursor:
      return row[0]

  def save_host(self, mac_addr, ipv4_addr, ipv6_addr, ts):
    hid = self._get_hostid_for_mac(mac_addr)
    if hid:
      self.cursor.execute('UPDATE hosts SET last_seen=? WHERE id=?', (ts, hid))
    else:
      self.cursor.execute('INSERT INTO hosts(mac_addr, ipv4_addr, ipv6_addr, first_seen, last_seen)'
                          ' VALUES (?,?,?,?,?)', (mac_addr, ipv4_addr, ipv6_addr, ts, ts))
    self.cursor.commit()

  def _get_identity(self, identity):
    self.cursor.execute('SELECT id FROM identities WHERE service=? AND event=? AND type=? AND value=?',
                        (identity.service, identity.event, identity.type, identity.value))
    for row in self.cursor:
      return row[0]

  def save_identity(self, identity, mac_addr):
    hid = self._get_hostid_for_mac(mac_addr)
    self.cursor.execute('INSERT INTO identities(host_id,service,event,type,value,certainty,'
                        'first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)',
                        (hid, identity.service, identity.event, identity.type, identity.value,
                         identity.certainty, identity.timestamp, identity.timestamp))
