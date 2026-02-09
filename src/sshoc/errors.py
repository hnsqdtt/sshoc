from __future__ import annotations


class SSHOCError(RuntimeError):
    pass


class ConfigError(SSHOCError):
    pass


class ToolError(SSHOCError):
    pass


class OutputLimitExceeded(SSHOCError):
    def __init__(self, *, stream: str, limit_bytes: int):
        super().__init__(f"{stream} exceeded max bytes limit ({limit_bytes})")
        self.stream = stream
        self.limit_bytes = limit_bytes

