__author__ = 'Alexander'

import sys, re
from os import sep
from libs import tracert, whois

if len(sys.argv[1:])<1:
    print('Not enough arguments')
    exit(-1)

ip = sys.argv[1]

with open('Libs'+sep+'iana_ip_base', 'r') as f:
    iana_ip_base = dict()
    for line in f:
        spl = line.strip().split(' ')
        iana_ip_base[spl[0]] = spl[1]

ipregexp = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
addrregexp = r'.+?\s*?\[(?P<IP>.*?)\]'

print('Tracing to {}'.format(ip))

for n, addr in enumerate(tracert.tracert(ip), 1):
    match = re.match(ipregexp, addr)
    if not match:
        match = re.match(addrregexp, addr)
        if match:
            addr = match.group('IP')
    as_string = ''
    if addr.split('.')[0] in iana_ip_base:
        rir = iana_ip_base[addr.split('.')[0]]
        as_info = dict()
        for field, value, comment in whois.whois_iter(rir, addr):
            if field=='origin' or field=='mnt-by':
                if field not in as_info:
                    as_string+= value+' '
                    as_info[field] = value

    if as_string=='': as_string='Unknown'

    print('{0}\t{1}\t {2}'.format(n, addr, as_string))

print('Complete')

