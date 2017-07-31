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
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

######################################

protocol = 'http://'
ip = "192.168.1.1"

sess = requests.Session()
sess.headers = {
    'User-Agent': UserAgent().chrome,
}

sess.get(protocol + ip)
r = sess.post(
    protocol + ip + '/cgi-bin/index2.asp',
    data = {
        'Logoff': '0',
        'Password': 'nE7jA%5m',
        'Password1': 'nE7jA%5m',
        'Password2': 'nE7jA%5m',
        'Username': 'useradmin',
        'hLoginTimes': '0',
        'hLoginTimes_Zero': '0',
        'logintype': 'usr',
        'value_one': '1',
    }
)

