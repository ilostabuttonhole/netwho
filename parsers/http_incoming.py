import re
from base_parser import BaseParser, Identity

class HttpIncomingParser(BaseParser):
  SPORTS = [80, 8000, 8080]
  PROTOCOL = 'HTTP'

  GOOGLE_USERMAIL_RE = re.compile('"userEmail":"(.*?)"')
  GOOGLE_UJ_RE = re.compile('&uj=(.*?)\&')
  TWITTER_RE = re.compile('<meta payload="(.*?)" name="session-user-screen_name" />')
  FLICKR_RE = re.compile('href="/photos/(\w+)/" id="personmenu_your_photos_link')
  PICASAWEB_ALBUM_RE = re.compile('/lh/people?uname=(\w+)&amp;isOwner=true')
  PICASAWEB_AUTHOR_RE = re.compile('/lh/people?uname=(\w+)&amp;isOwner=true')
  PICASAWEB_AUTH_USER_RE=re.compile("'authUserNickname':'(.*?)',")
  GMAIL_UGN_RE = re.compile(',\["ugn","(.*?)"\]')
  YOUTUBE_TITLE_RE = re.compile("- (\w+)'s  YouTube")
  YOUTUBE_UTIL_LINKS_RE = re.compile("UtilLinks\/Username\'\)\;\"\>(.*?)\<\/a\>")
  FACEBOOK_MENU_LINK_RE = re.compile("ref=name\" class=\"fb_menu_link\">(.*?)\<\/a\>")
  FACEBOOK_PROFILE_TITLE_RE = re.compile('ref=profile","title":"Facebook \| (.*?)"')
  GMAIL_CFS_RE = re.compile('\["cfs",\[\["(.*?)","(.*?\@.*?)",1,""\]')
  GOOGLE_GUSER_RE = re.compile("div id=guser width=100%\>\<nobr\>\<b\>(.*?\@.*?)\<\/b\>")
  FACEBOOK_PROFILE_STATUS_RE = re.compile('profile_name_and_status.*?\<h1 id=.*?profile_name.*?>(.*?)\<.*?h1')

  def parse(self, pkt, payload):
    match = self.GOOGLE_USERMAIL_RE.search(payload)
    if match:
      yield Identity(service='Google Account', event='Access', type='login',
                     value=match.group(1), certainty=0.8)
      yield Identity(service='Gmail', event='Access', type='login',
                     value=match.group(1), certainty=0.8)
      yield Identity(service='Gmail', event='Access', type='email',
                     value=match.group(1), certainty=0.5)

    # Used by Google
    match = self.GOOGLE_UJ_RE.search(payload)
    if match:
      yield Identity(service='Google Account', event='Access', type='login',
                     value=match.group(1), certainty=0.8)

    # Used by Twitter
    match = self.TWITTER_RE.search(payload)
    if match:
      yield Identity(service='Twitter', event='Access', type='handle',
                     value=match.group(1), certainty=0.8)

    match = self.FLICKR_RE.search(payload)
    if match:
      yield Identity(service='Flickr', event='Access', type='handle',
                     value=match.group(1), certainty=0.7)

    match = self.PICASAWEB_ALBUM_RE.search(payload)
    if match:
      yield Identity(service='PicasaWeb', event='Access', type='handle',
                     value=match.group(1), certainty=0.4)

    match = self.PICASAWEB_AUTH_USER_RE.search(payload)
    if match:
      yield Identity(service='PicasaWeb', event='Access', type='handle',
                     value=match.group(1), certainty=0.4)

    match = self.YOUTUBE_TITLE_RE.search(payload)
    if match:
      yield Identity(service='YouTube', event='Access', type='login',
                     value=match.group(1), certainty=0.4)

    match = self.YOUTUBE_UTIL_LINKS_RE.search(payload)
    if match:
      yield Identity(service='YouTube', event='Access', type='login',
                     value=match.group(1), certainty=0.4)

    match = self.FACEBOOK_MENU_LINK_RE.search(payload)
    if match:
      yield Identity(service='Facebook', event='Access Main', type='name',
                     value=match.group(1), certainty=1)

    match = self.FACEBOOK_PROFILE_TITLE_RE.search(payload)
    if match:
      yield Identity(service='Facebook', event='Profile', type='name',
                     value=match.group(1), certainty=1)

    match = self.FACEBOOK_PROFILE_STATUS_RE.search(payload)
    if match:
      yield Identity(service='Facebook', event='Access', type='status',
                     value=match.group(1), certainty=1)

    match = self.GOOGLE_GUSER_RE.search(payload)
    if match:
      yield Identity(service='Google Account', event='Access', type='login',
                     value=match.group(1), certainty=0.5)

    match = self.GMAIL_CFS_RE.search(payload)
    if match:
      yield Identity(service='GMail', event='Access', type='name',
                     value=match.group(1), certainty=0.9)
      yield Identity(service='Google Account', event='Access', type='login',
                     value=match.group(2), certainty=0.7)
      yield Identity(service='GMail', event='Access', type='email',
                     value=match.group(2), certainty=0.5)

    match = self.GMAIL_UGN_RE.search(payload)
    if match:
      yield Identity(service='GMail', event='Access', type='name',
                     value=match.group(1), certainty=0.9)