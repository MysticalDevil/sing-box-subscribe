import tool,re
from urllib.parse import urlparse, unquote

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    if server_info.path:
      server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
    if '@' in server_info.netloc:
        _netloc = server_info.netloc.rsplit("@", 1)
    else:
        return None
    netquery = flatten_query(server_info.query)
    tls: Node = {
        'enabled': True,
        'insecure': False
    }
    node: Node = {
        'tag': unquote(server_info.fragment) or tool.genName()+'_trojan',
        'type': 'trojan',
        'server': re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0]),
        'server_port': int(_netloc[1].rsplit(":", 1)[1].split("/")[0]),
        'password': _netloc[0],
        'tls': tls
    }
    if netquery.get('allowInsecure') == '1':
        tls['insecure'] = True
    if netquery.get('alpn'):
        tls['alpn'] = netquery['alpn'].strip('{}').split(',')
    if netquery.get('sni'):
        tls['server_name'] = netquery.get('sni', '')
    if netquery.get('fp'):
        tls['utls'] = {
            'enabled': True,
            'fingerprint': netquery.get('fp')
        }
    if netquery.get('type'):
        if netquery['type'] == 'h2':
            node['transport'] = {
                'type':'http',
                'host':netquery.get('host', node['server']),
                'path':netquery.get('path', '/')
            }
        if netquery['type'] == 'ws':
            matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
            if netquery.get('host'):
                node['transport'] = {
                     'type':'ws',
                     'path':netquery.get('path', '/').rsplit("?ed=", 1)[0] if matches else netquery.get('path', '/'),
                     'headers': {
                         'Host': netquery.get('host')
                    }
                }
        elif netquery['type'] == 'grpc':
            node['transport'] = {
                'type':'grpc',
                'service_name':netquery.get('serviceName', '')
            }
    if netquery.get('protocol') in ['smux', 'yamux', 'h2mux']:
        multiplex: Node = {
            'enabled': True,
            'protocol': netquery['protocol']
        }
        node['multiplex'] = multiplex
        if netquery.get('max-streams'):
            multiplex['max_streams'] = int(netquery['max-streams'])
        else:
            multiplex['max_connections'] = int(netquery['max-connections'])
            multiplex['min_streams'] = int(netquery['min-streams'])
        if netquery.get('padding') == 'True':
            multiplex['padding'] = True
    return node
