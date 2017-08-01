#!/usr/bin/env python
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:

import logging
import requests
from fake_useragent import UserAgent


# Enabling debugging at http.client level (requests->urllib3->http.client)
# you will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# the only thing missing will be the response.body which is not logged.
try: # for Python 3
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection
HTTPConnection.debuglevel = 1

logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from requests
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("yip")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

######################################

protocol = 'http://'
address = "192.168.1.1"
login_url = protocol + address + '/cgi-bin/index2.asp'
content_url = protocol + address + '/cgi-bin/content.asp'

sess = requests.Session()
sess.headers = {
    'User-Agent': UserAgent().chrome,
}

username = 'useradmin'
password = 'nE7jA%5m'

sess.get(login_url)

sess.cookies.set(name='UID', value=username, domain=address, path='/')
sess.cookies.set(name='PSW', value=password, domain=address, path='/')

r = sess.get(content_url)

