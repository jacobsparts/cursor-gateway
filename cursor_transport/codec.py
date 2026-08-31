"""Cursor wire codec over the real extracted protobuf schema.

Drop-in replacement for the old capture-derived cursor_codec: same dict-based
interface and same key style, but the field numbers and types come from
schema, which is generated from Cursor's own .proto files.
"""

from . import schema
from . import wire

wire.MESSAGES.update(schema.MESSAGES)

F = wire.F
UNKNOWN = wire.UNKNOWN
MESSAGES = wire.MESSAGES
encode = wire.encode
decode = wire.decode

__all__ = ["F", "UNKNOWN", "MESSAGES", "encode", "decode"]
