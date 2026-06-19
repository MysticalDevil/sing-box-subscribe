import tool,json,re
from typing import Any
from urllib.parse import urlparse

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[8:]
    if not info or info.isspace():
        return None
    try:
        if info.find('?') > -1: #fuck奇葩的URI格式
            server_info = urlparse(info)
            netquery = flatten_query(server_info.query)
            try:
                _path = tool.b64Decode(server_info.path).decode('utf-8').split("@")
            except Exception:
                _path = (server_info.path).split("@")
            node: Node = {
                'tag': netquery.get('remarks', tool.genName()+'_vmess'),
                'type': 'vmess',
                'server': _path[1].split(":")[0],
                'server_port': int(_path[1].split(":")[1]),
                'uuid': _path[0].split(":")[-1],
                'security': _path[0].split(":")[0] if ':' in _path[0] else 'auto',
                'alter_id': int(netquery.get('alterId','0')),
                'packet_encoding': 'xudp'
            }
            if (netquery.get('tls') and netquery['tls'] != '') or (netquery.get('security') == 'tls'):
                tls: Node = {
                    'enabled': True,
                    'insecure': True,
                    'server_name': netquery.get('peer', '')
                }
                node['tls'] = tls
                if netquery.get('allowInsecure') == 0:
                    tls['insecure'] = False
                if netquery.get('sni'):
                    tls['server_name'] = netquery['sni']
                    tls['utls'] = {
                        'enabled': True,
                        'fingerprint': netquery.get('fp', 'chrome')
                    }
            if (netquery.get('obfs') == 'websocket') or (netquery.get('type') == 'ws'):
                # matches = re.search(r'\?ed=(\d+)$', netquery.get('path', '/'))
                transport: Node = {
                    'type': 'ws',
                    'path': netquery.get('path', '/').rsplit("?ed=", 1)[0],
                    'headers': {
                        'Host': netquery.get('host', '')  # 如果 'obfsParam' 不存在或解析失败，使用 'host' 字段
                    }
                }
                node['transport'] = transport
                
                obfs_param = netquery.get('obfsParam', '')
                try:
                    obfs_param_json = json.loads(obfs_param)
                    host_from_obfs_param = obfs_param_json.get('Host', '')
                    transport['headers']['Host'] = host_from_obfs_param or netquery.get('host', '')
                except json.JSONDecodeError:
                    pass  # JSON 解码失败时忽略异常
            return node
        else:
            proxy_str = tool.b64Decode(info).decode('utf-8')
    except Exception:
        print(info)
        return None
    try:
        item: dict[str, Any] = json.loads(proxy_str)
    except Exception:
        return None
    ps = item.get('ps')
    port = item.get('port')
    if port is None:
        return None
    content = str(ps).strip() if ps else tool.genName()+'_vmess'
    node: Node = {
        'tag': content,
        'type': 'vmess',
        'server': item.get('add'),
        'server_port': int(port),
        'uuid': item.get('id'),
        'security': item.get('scy') if item.get('scy') not in ['http', None] else 'auto',
        'alter_id': int(item["aid"] if item.get("aid") else '0'),
        'packet_encoding': 'xudp'
    }
    if node['security'] == 'gun':
        node['security'] = 'auto'
    if 'tls' in item and (item['tls'] != '' and item['tls'] != 'none'):
        tls = {
            'enabled': True,
            'insecure': True,
            'server_name': item.get('host', '') if item.get("net") not in ['h2', 'http'] else ''
        }
        node['tls'] = tls
        if item.get('verify_cert') is False:
            tls['insecure'] = False
        if item.get('sni'):
            tls['server_name'] = item['sni']
        if item.get('fp'):
            tls['utls'] = {
                'enabled': True,
                'fingerprint': item['fp']
            }
    if item.get("net"):
        if item['net'] in ['h2', 'http', 'tcp']:
            transport = {
                'type':'http'
            }
            node['transport'] = transport
            if item.get('headers'):
                transport['headers'] = item['headers']
            if item.get('host'):
                transport['host'] = item['host']
            if item.get('path'):
                if isinstance(item.get('path'), str):
                    transport['path'] = item['path'].rsplit("?")[0]
                else:
                    transport['method'] = 'GET'
                    transport['path'] = item['path'][0]
        elif item['net'] == 'ws':
            transport: Node = {
                'type': 'ws'
            }
            node['transport'] = transport
            if item.get('host'):
                transport = {
                'type': 'ws',
                'headers': {
                    'Host': item['host']
                }
            }
                node['transport'] = transport
            if item.get('path'):
                path = str(item['path'])
                matches = re.search(r'\?ed=(\d+)$', path)
                transport['path'] = path.rsplit("?ed=", 1)[0] if matches else path
                if matches:
                    transport['early_data_header_name'] = 'Sec-WebSocket-Protocol'
                    transport['max_early_data'] = int(path.rsplit("?ed=", 1)[1])
        elif item['net'] == 'quic':
            node['transport'] = {
                'type':'quic'
            }
        elif item['net'] == 'grpc':
            node['transport'] = {
                'type':'grpc',
                'service_name':item.get('path', '')
            }
    if item.get('protocol') in ['smux', 'yamux', 'h2mux']:
        multiplex: Node = {
            'enabled': True,
            'protocol': item['protocol']
        }
        node['multiplex'] = multiplex
        if item.get('max_streams'):
            multiplex['max_streams'] = int(item['max_streams'])
        else:
            multiplex['max_connections'] = int(item['max_connections'])
            multiplex['min_streams'] = int(item['min_streams'])
        if item.get('padding') is True:
            multiplex['padding'] = True
    return node
