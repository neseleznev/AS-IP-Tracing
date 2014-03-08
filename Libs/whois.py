__author__ = 'Alexander'

import telnetlib, re

def get_server_whois_info(host, port, ip):
    tn = telnetlib.Telnet(host, port)
    tn.write('{}\n'.format(ip).encode())
    response = tn.read_all().decode()
    tn.close()
    return response

def whois(host, ip, field, port='43'):
    response = get_server_whois_info(host, port, ip)

    #regexp = r'\n{0}:\s*?(?P<field>\w[\w\s]*)(?P<comment>\s#.*\n)?\n'.format(field)
    regexp = r'\n{0}:\s*?(?P<value>\w[\w\s]*)\n'.format(field)
    match = re.search(regexp, response)
    if match:
        return match.group('value')
    return None

def whois_iter(host, ip, port='43'):
    response = get_server_whois_info(host, port, ip)
    regexp = re.compile(r'(?P<field>\w.+?):\s*?(?P<value>\w.*)')
    comments = list()
    for line in response.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('%'):
            comments.append(line)
            continue
        comment = False
        if line.find('#')!=-1:
            comments.append(line[line.find('#')+2:])
            line = line[:line.find('#')]
            comment = True
        match = re.search(regexp, line)
        if match:
            yield match.group('field'),\
                  match.group('value'),\
                  comments[-1] if comment else None
