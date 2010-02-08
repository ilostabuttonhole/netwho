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

"""Tests for GZIP preprocessor."""

__author__ = 'thomas%stromberg.org (Thomas Stromberg)'

from scapy.all import sniff
import unittest
import http_gzip

class HttpGzipTestCase(unittest.TestCase):
  def _load_testdata(self, file_path):
    packets = []
    def _add_packet(pkt):
      packets.append(pkt)

    path = '../testdata/http/' + file_path
    sniff(prn=_add_packet, store=0, offline=path)
    return packets

  def test_redirect_packet(self):
    """http://www.google.com/ request - first redirects to google.be"""
    preproc = http_gzip.GzipDecoder()
    test_data = self._load_testdata('www_google_com_firefox.pcap')
    (handled, data) = preproc.parse(test_data[1])
    self.assertEquals(handled, False)
    self.assertEquals(data, None)

  def test_www_google_com(self):
    """http://www.google.com/ request - contains gzip-encoded page."""
    preproc = http_gzip.GzipDecoder()
    test_data = self._load_testdata('www_google_com_firefox.pcap')
    for pkt in test_data:
      (handled, data) = preproc.parse(pkt)
      if data:
        break
    self.assertEquals(handled, True)
    self.assertTrue('helixblue@gmail.com' in data)

  def test_www_google_com_profiles(self):
    """This stream is a easy multi-packet gzip-encoded page."""
    preproc = http_gzip.GzipDecoder()
    test_data = self._load_testdata('www_google_com_profiles-sitemap.pcap')
    for pkt in test_data:
      (handled, data) = preproc.parse(pkt)
      if data:
        break
    self.assertEquals(handled, True)
    self.assertFalse('helixblue@gmail.com' in data)
    self.assertTrue('<lastmod>2009-10-08</lastmod>' in data)

  def test_www_google_com_last_packet(self):
    """HTTP/1.0 304 Not Modified."""
    preproc = http_gzip.GzipDecoder()
    test_data = self._load_testdata('www_google_com_firefox.pcap')
    self.assertEquals(preproc.parse(test_data[-1]), (False, None))


  def test_non_gzip_packet(self):
    """This stream has no gzip encoded packets."""
    preproc = http_gzip.GzipDecoder()
    test_data = self._load_testdata('www_google_com_sitemap.pcap')
    self.assertEquals(preproc.parse(test_data[0]), (False, None))
    self.assertEquals(preproc.parse(test_data[1]), (False, None))
    self.assertEquals(preproc.parse(test_data[2]), (False, None))
    self.assertEquals(preproc.parse(test_data[3]), (False, None))


if __name__ == '__main__':
    unittest.main()

