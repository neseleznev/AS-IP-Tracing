#!/usr/bin/env python
# -*- coding: cp1251 -*-
__author__ = 'Alexander'

import telnetlib, re

regexp = re.compile(r'(?P<field>\w.+?):\s*?(?P<value>\w.*)')

def get_server_whois_info(host, port, ip):
    tn = telnetlib.Telnet(host, port)
    tn.write(('%s\n' % ip).encode())
    response = tn.read_all().decode()
    tn.close()
    return response


def whois(host, ip, field, port='43'):
    response = get_server_whois_info(host, port, ip)
    #r'\n{0}:\s*?(?P<field>\w[\w\s]*)(?P<comment>\s#.*\n)?\n'.format(field)
    value_re = r'\n{0}:\s*?(?P<value>\w[\w\s]*)\n'.format(field)
    match = re.search(value_re, response)
    if match:
        return match.group('value')
    return None


def whois_iter(host, ip, port='43'):
    response = get_server_whois_info(host, port, ip)
    comments = list()
    for line in response.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('%'):
            comments.append(line)
            continue
        comment = False
        if line.find('#') != -1:
            comments.append(line[line.find('#') + 2:])
            line = line[:line.find('#')]
            comment = True
        match = re.search(regexp, line)
        if match:
            yield (match.group('field'),
                  match.group('value'),
                  comments[-1] if comment else None
            )
