#!/usr/bin/env python
# -*- coding: cp1251 -*-
__author__ = 'Alexander'

import sys, subprocess, re

searcher = re.compile(
    ur'\s*?(?P<number>\d+?)\s+?(?P<time1>(\d+ ms)|\*)\s+?(?P<time2>(\d+ ms)|\*)\s+?(?P<time3>(\d+ ms)|\*)\s+?(?P<addr>\S.*)',
    re.UNICODE
)


def tracert(ip, verbose=False):
    p = subprocess.Popen(['tracert', ip], stdout=subprocess.PIPE)
    
    while True:
        line = p.stdout.readline()
        if not line:
            break
        line = line.decode('cp866').strip()
        match = re.search(searcher, line)
        if match:
            if not verbose:
                yield (match.group('addr'), )
            else:
                yield (
                    match.group('number'),
                    match.group('time1'),
                    match.group('time2'),
                    match.group('time3'),
                    match.group('addr')
                )
