import tool,re
from urllib.parse import urlparse

from parsers._typing import Node, ParseResult, flatten_query

def parse(data: str) -> ParseResult:
    info = data[:]
    server_info = urlparse(info)
    if server_info.path:
        server_info = server_info._replace(netloc=server_info.netloc + server_info.path)
    _netloc = server_info.netloc.rsplit("@", 1)
    #_netloc = (tool.b64Decode(server_info.netloc)).decode().split("@")
    netquery = flatten_query(server_info.query)
    port_match = re.search(r'\d+', _netloc[1].rsplit(":", 1)[1])
    if port_match is None:
        return None
    tls: Node = {
        'enabled': True,
        'alpn': (netquery.get('alpn') or "h3").strip('{}').split(','),
        'insecure': False
    }
    node: Node = {
        'tag': server_info.fragment or tool.genName()+'_tuic',
        'type': 'tuic',
        'server': re.sub(r"\[|\]", "", _netloc[1].rsplit(":", 1)[0]),
        'server_port': int(port_match.group(0)),
        'uuid': _netloc[0].split(":")[0],
        'password': _netloc[0].split(":")[1] if len(_netloc[0].split(":")) > 1 else netquery.get('password', ''),
        'congestion_control': netquery.get('congestion_control', 'bbr'),
        'udp_relay_mode': netquery.get('udp_relay_mode'),
        'zero_rtt_handshake': False,
        'heartbeat': '10s',
        'tls': tls
    }
    if netquery.get('allow_insecure') == '1' :
        tls['insecure'] = True
    if netquery.get('disable_sni') and netquery['disable_sni'] != '1':
        tls['server_name'] = netquery.get('sni', netquery.get('peer', ''))
    if netquery.get('sni') or netquery.get('peer'):
        tls['server_name'] = netquery.get('sni', netquery.get('peer', ''))
    return node
