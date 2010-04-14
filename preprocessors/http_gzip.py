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

"""Preprocessor to handle GZIP packet reassembly."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'


import re
import gzip
import zlib
import StringIO
from scapy.all import TCP, IP, hexdump

MAX_SESSION_LENGTH = 65535

class GzipDecoder(object):

  """Decodes HTTP packets containing gzip data."""

  SPORTS = [80, 8000, 8080]
  DPORTS = []
  LAYER = TCP
  CONTENT_LENGTH_RE = re.compile('Content-Length: (\d+)', re.MULTILINE | re.IGNORECASE)
  CHUNKED_ENCODING_RE = re.compile('Transfer-encoding: chunked', re.MULTILINE | re.IGNORECASE)
  CHUNK_SIZE_RE = re.compile('^([0-9a-f]+)')

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
      print '- has session: %s' % session_id
      self.sessions[session_id][2].append(payload)
      data = self._attempt_reassembly(session_id)
      if data:
        return (True, data)
      else:
        return (True, None)

    # If this is a new HTTP packet
    if 'content-type: ' in payload.lower():
      if 'content-encoding: gzip' in payload.lower():
        if self.CHUNKED_ENCODING_RE.search(payload):
          is_chunked = True
        else:
          is_chunked = False

        print "- gzip encoded HTTP packet: %s bytes (chunked=%s)" % (len(payload), is_chunked)
        # Find out where the data actually starts.
        content_location = payload.find('\r\n\r\n')
        content_length = self._get_content_length(payload)
        gzip_content = payload[content_location+4:]

        # If we think we can decompress it now, do so and be heros.
        if len(gzip_content) >= content_length:
          data = self._smart_decompress(gzip_content, is_chunked, length=content_length)
          if data:
            return (True, data)

        # Otherwise, normal handling of session packets.
        self.sessions[session_id] = (content_length, is_chunked, [gzip_content])
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
    (content_length, is_chunked, fragments) = self.sessions[session_id]
    content = ''.join(fragments)
#    print '%s reassm: %s - need %s' % (session_id, len(content), content_length)
    if not content_length or len(content) >= content_length:
      decompressed = self._smart_decompress(content, is_chunked, length=content_length)
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
      if extracted:
        print "decompress %s bytes: extracted %s bytes" % (len(data), len(extracted))
      return extracted
    except zlib.error:
      print "decompress %s bytes: zlib.error" % len(data)
      pass
    except IOError:
      print "decompress %s bytes: IOError" % len(data)
      pass
    except:
      print '- Unusual error when decompressing stream (ignoring)'

    return extracted

  def _smart_decompress(self, data, is_chunked, length=None):
    """Decompress gzipped data, taking length into account.

    Args:
      data: a string of data to decompress
      length: the expected length of the data
    """
    extracted = None
    if is_chunked:
      print "WE ARE CHUNKED: %s bytes" % len(data)
      extracted_chunks = []  
      # TODO(tstromberg): Measure the size of each chunk
      if data[-2:] == '\r\n':
        chunks = data.split('\r\n[0-9a-f]+\r\n')
        for chunk in chunks:
          print "processing chunk size: %s" % len(chunk)
          match = self.CHUNK_SIZE_RE.search(chunk)
          if match:
            size = int(match.group(1), 16)
            print "found chunk size: %s" % size
            content_location = chunk.find('\r\n') + 2
            chunk_content = chunk[content_location:content_location+size]
            extracted = self._decompress(chunk_content)
            if extracted:
              extracted_chunks.append(extracted)
            else:
              print "unable to extract chunk of %s bytes" % len(chunk_content)
              print hexdump(chunk_content)
        if extracted_chunks:
          print "%s chunks of %s chunks extracted." % (len(extracted_chunks), len(chunks))
          return ''.join(extracted_chunks)
      else:
        print "chunk end not found, waiting: %s bytes" % len(data)
      
    if length and len(data) > length:
      try_data = data[:length]
      extracted = self._decompress(try_data)

    if not extracted:
      extracted = self._decompress(data)
    
    return extracted
