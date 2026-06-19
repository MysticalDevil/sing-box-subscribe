import tool,re
from urllib.parse import urlparse, unquote

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    netquery = flatten_query(server_info.query)
    if server_info.path:
      server_info = server_info._replace(netloc=server_info.netloc + server_info.path, path="")
    ports_match = re.search(r',(\d+-\d+)', server_info.netloc)
    server_port_match = re.search(r'\d+', server_info.netloc.rsplit(":", 1)[-1].split(",")[0])
    if server_port_match is None:
        return None
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
        'tag': unquote(server_info.fragment) or tool.genName()+'_hysteria2',
        'type': 'hysteria2',
        'server': re.sub(r"\[|\]", "", server_info.netloc.split("@")[-1].rsplit(":", 1)[0]),
        'server_port': int(server_port_match.group(0)),
        "password": netquery['auth'] if netquery.get('auth') else server_info.netloc.split("@")[0].rsplit(":", 1)[-1],
        'up_mbps': int(up_match.group(0)),
        'down_mbps': int(down_match.group(0)),
        'tls': tls
    }
    if ports_match:
        node['server_ports'] = [ports_match.group(1).replace('-', ':')]
    if netquery.get('insecure') in ['1', 'true'] or netquery.get('allowInsecure') == '1':
        tls['insecure'] = True
    if not tls.get('server_name'):
        del tls['server_name']
        tls['insecure'] = True
    elif tls['server_name'] == 'None':
        del tls['server_name']
    tls['alpn'] = (netquery.get('alpn') or "h3").strip('{}').split(',')
    if netquery.get('obfs', '') not in ['none', '']:
        node['obfs'] = {
            'type': netquery['obfs'],
            'password': netquery['obfs-password'],
        }
    return (node)
