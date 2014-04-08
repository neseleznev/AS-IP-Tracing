#!/usr/bin/env python
# -*- coding: cp1251 -*-
__author__ = 'Alexander'

import sys, os, re
import tracert, whois


def parse_args():
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='AS-IP-Tracing. Autonomous System tracing tool.'
        )
        parser.add_argument('address',
            help="Server`s IP or domain_name. For example, 8.8.8.8 or ya.ru"
        )
        parser.add_argument('--verbose',
            action='store_true', help="Enable verbose mode"
        )
        args = vars(parser.parse_args())
    except ImportError:
        print("Module argparse is not installed, try 'pip install argparse'")
        sys.exit(1)
    return args


def main():

    args = parse_args()

    ip = args['address']
    verbose = args['verbose']

    with open(os.path.join('data', 'iana_ip_base'), 'r') as db:
        iana_ip_base = dict()
        for line in db:
            key, value = line.strip().split(' ')
            iana_ip_base[key] = value

    ipregexp = re.compile(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')
    addrregexp = re.compile(r'.+?\s*?\[(?P<IP>.*?)\]')

    print('Tracing to %s\n' % ip)

    for n, info in enumerate(tracert.tracert(ip, verbose), 1):
        addr = info[-1]
        as_name = ''

        match = re.match(ipregexp, addr)
        if not match:
            match = re.match(addrregexp, addr)
            if match:
                addr = match.group('IP')

        if addr.split('.')[0] in iana_ip_base:
            rir = iana_ip_base[addr.split('.')[0]]
            as_info = dict()
            for field, value, comment in whois.whois_iter(rir, addr):
                if field == 'origin' or field == 'mnt-by':
                    if field not in as_info:
                        as_name += value + ' '
                        as_info[field] = value
        elif verbose:
            print('Can not find <%s> in iana ip base' % addr)
        
        if verbose:
            info_str = u''
            for el in info[1:]:
                try:
                    el_str = str(el)
                except UnicodeEncodeError:
                    el_str += ' -TimeLimitExceeded'
                info_str += el_str + ' | '
        else:
            info_str = addr

        print(u'%d\t%s\t%s' % (n, info_str, as_name if as_name else 'Unknown'))

    print('Completed')


if __name__ == '__main__':
    main()
