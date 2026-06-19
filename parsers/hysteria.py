import tool,re
from urllib.parse import urlparse, unquote

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    netquery = flatten_query(server_info.query)
    up_match = re.search(r'\d+', netquery.get('upmbps', '10'))
    down_match = re.search(r'\d+', netquery.get('downmbps', '100'))
    if up_match is None or down_match is None:
        return None
    tls: Node = {
        'enabled': True,
        'server_name': netquery.get('sni', netquery.get('peer', '')),
        'insecure': False
    }
    node: Node = {
        'tag': unquote(server_info.fragment) or tool.genName()+'_hysteria',
        'type': 'hysteria',
        'server': re.sub(r"\[|\]", "", server_info.netloc.rsplit(":", 1)[0]),
        'server_port': int((server_info.netloc.rsplit(":", 1)[1]).split(",", 1)[0]), #fuck all
        'up_mbps': int(up_match.group(0)),
        'down_mbps': int(down_match.group(0)),
        'auth_str': netquery.get('auth', ''),
        'tls': tls
    }
    if netquery.get('alpn'):
        tls['alpn'] = netquery['alpn'].strip('{}').split(',')
    if netquery.get('insecure') == '1' or netquery.get('allowInsecure') == '1':
        tls['insecure'] = True
    if netquery.get('obfs') and netquery['obfs'] != 'none':
        node['obfs'] = netquery.get('obfs')
    return node
