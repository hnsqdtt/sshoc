from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Iterable


Json = dict[str, Any]


@dataclass(frozen=True)
class JSONRPCErrorPayload:
    code: int
    message: str
    data: Any | None = None


def _jsonrpc_error(*, id_value: Any, code: int, message: str, data: Any | None = None) -> Json:
    payload: Json = {"code": code, "message": message}
    if data is not None:
        payload["data"] = data
    return {"jsonrpc": "2.0", "id": id_value, "error": payload}


def read_messages(stream: Iterable[str]) -> Iterable[Json]:
    for line in stream:
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def _strip_surrogates(s: str) -> str:
    """Replace lone surrogates (U+D800-U+DFFF) so JSON serialisation never fails."""
    return s.encode("utf-8", errors="replace").decode("utf-8")


def write_message(msg: Json) -> None:
    try:
        text = json.dumps(msg, ensure_ascii=False)
    except UnicodeEncodeError:
        text = json.dumps(msg, ensure_ascii=True)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def safe_call(fn, *, request_id: Any, debug: bool) -> Json:
    try:
        result = fn()
        if not isinstance(result, dict):
            raise TypeError(f"handler must return dict result, got {type(result).__name__}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except (TypeError, ValueError, KeyError) as exc:
        data = None
        if debug:
            data = {"traceback": traceback.format_exc()}
        return _jsonrpc_error(
            id_value=request_id,
            code=JSONRPCInvalidParams,
            message=f"{type(exc).__name__}: {exc}",
            data=data,
        )
    except Exception as exc:
        data = None
        if debug:
            data = {"traceback": traceback.format_exc()}
        return _jsonrpc_error(
            id_value=request_id,
            code=-32000,
            message=f"{type(exc).__name__}: {exc}",
            data=data,
        )


JSONRPCMethodNotFound = -32601
JSONRPCInvalidRequest = -32600
JSONRPCInvalidParams = -32602
JSONRPCParseError = -32700
