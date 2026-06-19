from typing import Any
from urllib.parse import parse_qs

type Node = dict[str, Any]
type ParseResult = Node | tuple[Node, Node] | None


def flatten_query(query: str) -> dict[str, str]:
    return {key: values[-1] if values else "" for key, values in parse_qs(query).items()}
