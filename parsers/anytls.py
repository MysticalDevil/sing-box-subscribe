import tool,re
from urllib.parse import urlparse, unquote

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    netquery = flatten_query(server_info.query)
    tls: Node = {
        'enabled': True,
        'server_name': netquery.get('sni', netquery.get('peer', '')),
        'insecure': False
    }
    node: Node = {
        'tag': unquote(server_info.fragment) or tool.genName()+'_anytls',
        'type': 'anytls',
        'server': re.sub(r"\[|\]", "", server_info.netloc.split("@")[-1].rsplit(":", 1)[0]),
        'server_port': int((server_info.netloc.rsplit(":", 1)[1]).split(",", 1)[0]), #fuck all
        'password': netquery['auth'] if netquery.get('auth') else server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
        'tls': tls
    }
    if netquery.get('idleSessionCheckInterval'):
        node['idle_session_check_interval'] = netquery['idleSessionCheckInterval']+'s'
    if netquery.get('idleSessionTimeout'):
        node['idle_session_timeout'] = netquery['idleSessionTimeout']+'s'
    if netquery.get('minIdleSession'):
        node['min_idle_session'] = int(netquery['minIdleSession'])
    if netquery.get('fp'):
        tls['utls'] = {
            'enabled': True,
            'fingerprint': netquery.get('fp')
        }
    if netquery.get('alpn'):
        tls['alpn'] = netquery['alpn'].strip('{}').split(',')
    if netquery.get('insecure') == '1' or netquery.get('allowInsecure') == '1':
        tls['insecure'] = True
    return node
