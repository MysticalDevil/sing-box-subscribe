import tool,re
from urllib.parse import urlparse, unquote

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    try:
        netloc = tool.b64Decode(server_info.netloc).decode('utf-8')
    except Exception:
        netloc = server_info.netloc
    _netloc = netloc.split("@")
    try:
        _netloc_parts = _netloc[1].rsplit(":", 1)
    except Exception:
        return None
    if _netloc_parts[1].isdigit(): #fuck
        server = re.sub(r"\[|\]", "", _netloc_parts[0])
        server_port = int(_netloc_parts[1])
    else:
        return None
    netquery = flatten_query(server_info.query)
    if netquery.get('remarks'):
        remarks = netquery['remarks']
    else:
        remarks = server_info.fragment
    node: Node = {
        'tag': unquote(remarks) or tool.genName()+'_vless',
        'type': 'vless',
        'server': server,
        'server_port': server_port,
        'uuid': _netloc[0].split(':', 1)[-1],
        'packet_encoding': netquery.get('packetEncoding', 'xudp')
    }
    if netquery.get('flow'):
        node['flow'] = 'xtls-rprx-vision'
    if netquery.get('security', '') not in ['None', 'none', ''] or netquery.get('tls') == '1':
        tls: Node = {
            'enabled': True,
            'insecure': False,
            'server_name': ''
        }
        node['tls'] = tls
        if netquery.get('allowInsecure') == '1':
            tls['insecure'] = True
        tls['server_name'] = netquery.get('sni', '') or netquery.get('peer', '')
        if tls['server_name'] == 'None':
            tls['server_name'] = ''
        if netquery.get('security') == 'reality' or netquery.get('pbk'): #shadowrocket
            reality: Node = {
                'enabled': True,
                'public_key': netquery.get('pbk'),
            }
            tls['reality'] = reality
            # 处理 short_id，避免 fuck 'None' 或 null
            sid = netquery.get('sid')
            if isinstance(sid, str) and sid.strip().lower() != "none":
                reality['short_id'] = netquery['sid']
            tls['utls'] = {
                'enabled': True
            }
            if netquery.get('fp'):
                tls['utls'] = {
                    'enabled': True,
                    'fingerprint': netquery['fp']
                }
    if netquery.get('type'):
        if netquery['type'] == 'http':
            node['transport'] = {
                'type':'http'
            }
        elif netquery['type'] == 'ws':
            matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
            transport: Node = {
                'type':'ws',
                "path": netquery.get('path', '/').rsplit("?ed=", 1)[0] if matches else netquery.get('path', '/'),
                "headers": {
                    "Host": '' if netquery.get('host') is None and netquery.get('sni') == 'None' else netquery.get('host', netquery.get('sni', ''))
                }
            }
            node['transport'] = transport
            if node.get('tls'):
                tls = node['tls']
                if tls['server_name'] == '':
                    if transport['headers']['Host']:
                        tls['server_name'] = transport['headers']['Host']
            if matches:
                transport['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                transport['max_early_data'] = int(netquery.get('path', '/').rsplit("?ed=", 1)[1])
        elif netquery['type'] == 'grpc':
            node['transport'] = {
                'type':'grpc',
                'service_name':netquery.get('serviceName', '')
            }
    elif netquery.get('obfs'):  #shadowrocket
        if netquery['obfs'] == 'websocket':
            matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
            transport = {
                'type':'ws',
                "path": netquery.get('path', '/').rsplit("?ed=", 1)[0] if matches else netquery.get('path', '/'),
                "headers": {
                    "Host": '' if netquery.get('obfsParam') is None and netquery.get('sni') == 'None' else netquery.get('peer', netquery.get('obfsParam'))
                }
            }
            node['transport'] = transport
            if node.get('tls'):
                tls = node['tls']
                if tls['server_name'] == '':
                    if transport['headers']['Host']:
                        tls['server_name'] = transport['headers']['Host']
            if matches:
                transport['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                transport['max_early_data'] = int(netquery.get('path', '/').rsplit("?ed=", 1)[1])
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
