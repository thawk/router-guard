#!/usr/bin/env python3
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:

# Imports
import argparse
import codecs
import collections
import locale
import logging
import requests
import time
import yaml

from logging.handlers import SysLogHandler

PROG_NAME = 'router_guard'
VERSION = u'20171101'

DEFAULT_CONFIG_FILE = 'config.yaml'

DELAY_SECS = 1

# 对于配置文件中没有的会，此处作为缺省值
DEFAULT_CONFIG = {
    # 要模拟的浏览器
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.101 Safari/537.36',
    # 光猫相关配置
    'modem': {
        'address': '192.168.1.1',
        'protocol': 'http',
        'username': 'useradmin',
        'password': 'nE7jA%5m',
        # 检测光猫的连接超时时间
        'timeout': 5,
    },
    # 互联网检测的相关配置
    'internet': {
        # 用于检测的URL
        'url': 'http://www.baidu.com',
        # 检测超时时间
        'timeout': 5,
    },
    # 与拨号相关的配置
    'pppoe': {
        # 从光猫就绪到PPPOE拨号完成（互联网就绪）有一段时间，本配置控制最多等待的时间
        'timeout': 60,
    },
    'guard': {
        # 监控网络连接情况时，每隔多久（秒）检测一次
        'interval': 60,
    },
}


# verbose级别
VERBOSE_ACTION = 1  # 记录每次尝试
VERBOSE_RESULT = 2  # 记录每次尝试及结果
VERBOSE_HTTP = 3    # 记录每次的请求及响应

logger = logging.getLogger('router_guard')


class SyslogFilter(logging.Filter):
    """
    Filter messages by 'skip_syslog' property.
    """

    def filter(self, record):
        if record.__dict__.get('skip_syslog', False):
            return False

        return True


def dict_merge(dct, *merge_dcts):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.
    :param dct: dict onto which the merge is executed
    :param merge_dcts: dicts merged into dct
    :return: dct
    """
    for merge_dct in merge_dcts:
        for k, v in merge_dct.items():
            if (k in dct and isinstance(dct[k], dict)
                    and isinstance(merge_dct[k], collections.Mapping)):
                dict_merge(dct[k], merge_dct[k])
            else:
                dct[k] = merge_dct[k]

    return dct

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
    requests_log = logging.getLogger('yip')
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class RouterGuard(object):
    def __init__(self, config, verbose=0):
        super().__init__()

        self.config = config
        self.verbose  = verbose

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': self.config['user_agent'],
        }

        self.is_logined = False
        self.last_reboot = None

    def _get_modem_url(self, page):
        if len(page) > 0 and page[0] == '/':
            return (self.config['modem']['protocol'] + '://'
                    + self.config['modem']['address']
                    + page)
        else:
            return (self.config['modem']['protocol'] + '://'
                    + self.config['modem']['address'] + '/'
                    + page)

    def _exec(self, action, url, *args, **kwargs):
        try:
            if self.verbose >= VERBOSE_ACTION:
                logger.info('    {}'.format(url))

            r = action(url, *args, **kwargs)
            if self.verbose >= VERBOSE_RESULT:
                logger.info('      {}'.format(r.status_code))

            return (r.status_code, r.text)
        except Exception as ex:
            if self.verbose >= VERBOSE_RESULT:
                logger.info('      failed {url} with exception: {ex}'.format(url=url, ex=ex))

            return (0, '')

    def check_modem(self):
        """检查光猫的状态

        Returns:
          True  - 网页可以访问。通过检查is_logined属性可以判断是否已登录
          False - 网页不可访问
        """
        if self.verbose >= VERBOSE_ACTION:
            logger.info('  Check modem login status...')

        status_code, _ = self._exec(
            self.session.get, self._get_modem_url(''),
            timeout=self.config['modem']['timeout'])

        if status_code == requests.codes.ok:
            self.is_logined = True
            return True

        self.is_logined = False
        return status_code > 0

    def login(self):
        self.check_modem()

        if self.is_logined:
            return True

        if self.verbose >= VERBOSE_ACTION:
            logger.info('  Login to modem...')

        if self._exec(
                self.session.get,
                self._get_modem_url('/cgi-bin/index2.asp'),
                timeout=self.config['modem']['timeout'])[0] != requests.codes.ok:
            return False

        for n, v in self.config['modem']['cookies'].items():
            self.session.cookies.set(
                name=n, value=v.format(**self.config['modem']),
                domain=self.config['modem']['address'], path='/')

        if self._exec(
                self.session.get,
                self._get_modem_url('/cgi-bin/content.asp'),
                timeout=self.config['modem']['timeout'])[0] != requests.codes.ok:
            return False
        else:
            self.is_logined = True
            return True

    def logout(self):
        self.is_logined = False

        return self._exec(
            self.session.get,
            self._get_modem_url('/cgi-bin/logout.cgi'),
            timeout=self.config['modem']['timeout'])[0] == requests.codes.ok

    def reboot(self):
        ret = self._exec(
            self.session.post,
            self._get_modem_url('/cgi-bin/mag-reset.asp'),
            {
                'rebootflag': '1',
                'restoreFlag': '1',
                'isCUCSupport': '0',
            },
            timeout=self.config['modem']['timeout']
        )[0] == requests.codes.ok

        if ret:
            self.last_reboot = time.time()

        return ret

    def check_internet(self):
        return self._exec(
            requests.get,
            self.config['internet']['url'],
            timeout=self.config['internet']['timeout'])[0] > 0

    def detect_ip(self):
        for url in self.config['ip_detect']['urls']:
            status_code, ip = self._exec(
                requests.get,
                url,
                timeout=self.config['ip_detect']['timeout'])

            if status_code == requests.codes.ok:
                return ip

        return ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.is_logined:
            self.logout()

        # 未对异常进行处理
        return False

def check(router_guard):
    logger.info('Checking modem...')
    if not router_guard.check_modem():
        logger.warn('  Modem is unconnectable!!!')
        return False

    logger.info('Checking internet...')
    rc = router_guard.check_internet()

    logger.info('  Internet is OK.')

    logger.info('Detecting IP address...')
    ip = router_guard.detect_ip()

    if ip:
        logger.info('  IP address: {}'.format(ip))
    else:
        logger.info('  Failed to detect IP address')

    return rc

def reboot(router_guard):
    logger.info('  Login modem...')
    if router_guard.login():
        logger.warn('  Rebooting modem...')
        router_guard.reboot()

        logger.info('  Wait for modem reboot...')
        while True:
            time.sleep(DELAY_SECS)
            if not router_guard.check_modem():
                break

        timer_start = time.time()
        while True:
            logger.info('  Wait for modem ready...')

            while True:
                time.sleep(DELAY_SECS)
                if router_guard.check_modem():
                    break

            now = time.time()
            logger.info('    Modem ready in {} secs...'.format(int(now - timer_start)))

            timer_start = now

            logger.info('  Checking internet...')
            while True:
                if router_guard.check_internet():
                    logger.info('    Internet ready in {} secs...'.format(int(now - timer_start)))

                    logger.info('  Detecting IP address...')
                    ip = router_guard.detect_ip()

                    if ip:
                        logger.info('    IP address: {}'.format(ip))
                    else:
                        logger.info('  Failed to detect IP address')

                    return

                now = time.time()
                if now - timer_start > router_guard.config['pppoe']['timeout'] \
                        and not router_guard.check_modem():
                    # 在指定时间内，互联网还未就绪
                    logger.error(
                        '    Internet not ready after {} secs'.format(
                            now - timer_start))
                    break

                time.sleep(DELAY_SECS)

def guard(router_guard):
    while True:
        logger.info('Check internet...', extra={'skip_syslog': True})
        if not router_guard.check_internet():
            logger.warn('  Internet is unconnectable, check modem...')
            if router_guard.check_modem():
                if router_guard.last_reboot:
                    elapsed = time.time() - router_guard.last_reboot
                    logger.info('  Last reboot was {} ago'.format(
                        time.strftime("%H:%M:%S", time.gmtime(elapsed))))

                # 当互联网不可用但光猫可访问时，重启光猫
                logger.info('Reboot modem...')
                reboot(router_guard)
            else:
                logger.warn('  Modem is unconnectable too')

        time.sleep(router_guard.config['guard']['interval'])

def main(**args):
    logger.info('{} version {} running at {} mode'.format(
        PROG_NAME, VERSION, args['command']))

    if args['verbose'] >= VERBOSE_HTTP:
        enable_debugging()

    with open(args['config_file'], 'r') as f:
        config = yaml.load(f)

    config = dict_merge({}, DEFAULT_CONFIG, config)

    router_guard = RouterGuard(config, verbose=args['verbose'])

    if args['command'] == 'reboot':
        logger.info('Reboot modem...')
        reboot(router_guard)
    elif args['command'] == 'guard':
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
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG_FILE, action='store', dest='config_file', help=u'Configuration file')
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
    syslog.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    syslog.addFilter(SyslogFilter())

    logger.addHandler(syslog)

    main(**vars(args))
