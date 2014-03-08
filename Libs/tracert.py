__author__ = 'Alexander'

from subprocess import Popen, PIPE
import re, sys

def tracert(ip, verbose=False):
    p = Popen(['tracert', ip], stdout=PIPE)
    regexp = r'\s*?(?P<number>\d+?)\s+?(?P<time1>(\d+ ms)|\*)\s+?(?P<time2>(\d+ ms)|\*)\s+?(?P<time3>(\d+ ms)|\*)\s+?(?P<addr>\S.*)'
    while True:
        line = p.stdout.readline()
        if not line:
            break
        line = line.decode('cp866').strip()
        match = re.search(regexp, line)
        if match:
            if not verbose:
                yield match.group('addr')
            else:
                yield match.group('number'),\
                      match.group('time1'),\
                      match.group('time2'),\
                      match.group('time3'),\
                      match.group('addr')
