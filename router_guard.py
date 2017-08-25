#!/usr/bin/env python3
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:

# Imports
import argparse
import codecs
import locale
import logging
from logging.handlers import SysLogHandler
import requests
import time
from fake_useragent import UserAgent

PROG_NAME='router_guard'
VERSION=u'20170825'

GUARD_INTERVALS=60
DELAY_SECS=5

# verbose级别
VERBOSE_ACTION=1  # 记录每次尝试
VERBOSE_RESULT=2  # 记录每次尝试及结果
VERBOSE_HTTP=3    # 记录每次的请求及响应

logger = logging.getLogger('router_guard')

def enable_debugging():
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


class RouterGuard(object):
    def __init__(self, address, username, password, protocol='http', verbose=0):
        super().__init__()

        self.protocol = protocol
        self.address  = address
        self.username = username
        self.password = password
        self.verbose  = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': UserAgent().chrome,
        }

        self.is_logined = False

    def _get_url(self, page):
        if len(page) > 0 and page[0] == '/':
            return self.protocol + '://' + self.address + page
        else:
            return self.protocol + '://' + self.address + '/' + page

    def _exec(self, action, url, *args, **kwargs):
        try:
            if self.verbose >= VERBOSE_ACTION:
                logger.info("    {}".format(url))

            r = action(url, *args, **kwargs)
            if self.verbose >= VERBOSE_RESULT:
                logger.info("      {}".format(r.status_code))

            return r.status_code
        except Exception as ex:
            if self.verbose >= VERBOSE_RESULT:
                logger.info("      failed {url} with exception: {ex}".format(url=url, ex=ex))

            return 0

    def check_router(self):
        """检查路由器的状态

        Returns:
          True  - 网页可以访问。通过检查is_logined属性可以判断是否已登录
          False - 网页不可访问
        """
        if self.verbose >= VERBOSE_ACTION:
            logger.info("  Check router login status...")

        status_code = self._exec(self.session.get, self._get_url(''))

        if status_code == 200:
            self.is_logined = True
            return True

        self.is_logined = False
        return status_code > 0

    def login(self):
        self.check_router()

        if self.is_logined:
            return True

        if self.verbose >= VERBOSE_ACTION:
            logger.info("  Login to router...")

        if self._exec(self.session.get, self._get_url('/cgi-bin/index2.asp')) != 200:
            return False

        self.session.cookies.set(name='UID', value=self.username, domain=self.address, path='/')
        self.session.cookies.set(name='PSW', value=self.password, domain=self.address, path='/')

        if self._exec(self.session.get, self._get_url('/cgi-bin/content.asp')) != 200:
            return False
        else:
            self.is_logined = True
            return True

    def logout(self):
        self.is_logined = False

        return self._exec(self.session.get, self._get_url('/cgi-bin/logout.cgi')) == 200

    def reboot(self):
        return self._exec(
            self.session.post,
            self._get_url('/cgi-bin/mag-reset.asp'),
            {
                'rebootflag': '1',
                'restoreFlag': '1',
                'isCUCSupport': '0',
            }
        ) == 200

    def check_internet(self, url="http://www.baidu.com"):
        return self._exec(requests.get, url) > 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.is_logined:
            self.logout()

        # 未对异常进行处理
        return False

def check(router_guard):
    logger.info('Checking router...')
    if router_guard.check_router():
        logger.info('Checking internet...')
        router_guard.check_internet()

    logger.info('Done.')

def reboot(router_guard):
    logger.info('Login router...')
    if router_guard.login():
        logger.warn('Reboot router...')
        router_guard.reboot()

        while True:
            logger.info('Wait for router ready...')

            while True:
                time.sleep(DELAY_SECS)
                if router_guard.check_router():
                    break

            logger.info('Checking internet...')
            while True:
                if router_guard.check_internet():
                    logger.warn('  Done')
                    return

                if not router_guard.check_router():
                    break

                time.sleep(DELAY_SECS)

def guard(router_guard):
    while True:
        logger.info('Check internet...')
        if not router_guard.check_internet():
            logger.info('Check router...')
            if router_guard.check_router():
                # 当互联网不可用但路由器可访问时，重启路由器
                logger.info('Reboot router...')
                router_guard.reboot()

        time.sleep(GUARD_INTERVALS)

def main(**args):
    logger.info('{} version {} running at {} mode'.format(
        PROG_NAME, VERSION, args['command']))

    if args['verbose'] >= VERBOSE_HTTP:
        enable_debugging()

    router_guard = RouterGuard(
        address='192.168.1.1', protocol='http',
        username='useradmin',  password='nE7jA%5m',
        verbose=args['verbose'])

    if args['command'] == "reboot":
        reboot(router_guard)
    elif args['command'] == "guard":
        guard(router_guard)
    else:
        check(router_guard)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=u'''\
router_guard''')

    parser.add_argument('-v', '--verbose', action='count', dest='verbose', help=u'Be moderatery verbose')
    parser.add_argument('-q', '--quiet', action='store_true', dest='quiet', default=False, help=u'Only show warning and errors')
    parser.add_argument('--version', action='version', version=VERSION, help=u'Show version and quit')
    parser.add_argument('command', nargs='?', default='check', choices=['check', 'guard', 'reboot'], help=u'Command')

    args = parser.parse_args()

    if not args.verbose:
        args.verbose = 0

    # 日志初始化
    log_format = u'%(asctime)s %(levelname)s %(message)s'

    if args.quiet:
        logging.basicConfig(level=logging.WARNING, format=log_format)
    elif args.verbose >= VERBOSE_HTTP:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)

    syslog = SysLogHandler(address='/dev/log')
    syslog.ident = '{}: '.format(PROG_NAME)
    syslog.setLevel(logging.INFO)
    syslog.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    logger.addHandler(syslog)

    main(**vars(args))
