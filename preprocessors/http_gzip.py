import re
import gzip
import zlib
import StringIO
from scapy.all import TCP, IP

MAX_SESSION_LENGTH = 65535

class GzipDecoder(object):

  """Decodes HTTP packets containing gzip data."""

  SPORTS = [80, 8000, 8080]
  DPORTS = []
  LAYER = TCP
  CONTENT_LENGTH_RE = re.compile('Content-Length: (\d+)', re.MULTILINE)

  def __init__(self):
    # TODO(tstromberg): Make this an expiring dictionary to avoid memory leak.
    self.sessions = {}

  def parse(self, pkt):
    """Attempt to parse and pre-process said packet.

    Returns:
      handled: Boolean to show whether or not this packet is being preprocessed.
      data:    String of data yielded from the preprocessor.
    """
    payload = str(pkt[TCP].payload)
    if not payload:
      return (False, None)


    session_id = self._get_session_id(pkt)
#    print "---- ses: %s seq: %s [payload: %s]" % (session_id, pkt[TCP].seq, len(payload))
    if session_id in self.sessions:
#      print 'has session: %s' % session_id
      self.sessions[session_id][1].append(payload)
      data = self._attempt_reassembly(session_id)
      if data:
        return (True, data)
      else:
        return (True, None)

    # If this is a new HTTP packet
    if 'Content-Type: ' in payload:
      if 'Content-Encoding: gzip' in payload:
        # Find out where the data actually starts.
        content_location = payload.find('\r\n\r\n')
        content_length = self._get_content_length(payload)
        gzip_content = payload[content_location+4:]

        # If we think we can decompress it now, do so and be heros.
        if len(gzip_content) >= content_length:
          data = self._smart_decompress(gzip_content, length=content_length)
          if data:
            return (True, data)

        # Otherwise, normal handling of session packets.
        self.sessions[session_id] = (content_length, [gzip_content])
        return (True, None)
      # This is not a gzip-packet
      else:
        return (False, None)
    else:
      return (False, None)

  def _get_content_length(self, payload):
    """Get the content-length for an HTTP header if available."""
    match = self.CONTENT_LENGTH_RE.search(payload)
    if match:
      return int(match.group(1))
    else:
      return None

  def _get_session_id(self, pkt):
    """Return a unique session id for a session.

    Args:
      pkt - scapy packet

    Returns:
      session_id (string)
    """
    fields = [pkt[IP].fields['src'], pkt[TCP].sport, pkt[IP].fields['dst'],
              pkt[TCP].dport]
    return '.'.join(map(str, fields))


  def _attempt_reassembly(self, session_id):
    (content_length, fragments) = self.sessions[session_id]
    content = ''.join(fragments)
#    print '%s reassm: %s - need %s' % (session_id, len(content), content_length)
    if not content_length or len(content) >= content_length:
      decompressed = self._smart_decompress(content, length=content_length)
      if decompressed:
        del self.sessions[session_id]
      return decompressed

    if len(content) > MAX_SESSION_LENGTH:
      print '- Too much content, removing session %s' % session_id
      del self.sessions[session_id]

  def _decompress(self, data):
    """Attempt to decompress a stream without any smarts."""
    compressed_stream = StringIO.StringIO(data)
    decompressor = gzip.GzipFile(fileobj=compressed_stream)
    extracted = None
    try:
      extracted = decompressor.read()
#      print '- extracted gzip data!'
      return extracted
    except zlib.error:
      pass
    except IOError:
      pass
    return extracted

  def _smart_decompress(self, data, length=None):
    """Decompress gzipped data, taking length into account.

    Args:
      data: a string of data to decompress
      length: the expected length of the data
    """
    extracted = None
    if length and len(data) > length:
      try_data = data[:length]
      extracted = self._decompress(try_data)

    if not extracted:
      extracted = self._decompress(data)

    return extracted
