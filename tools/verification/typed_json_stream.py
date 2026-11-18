"""Bounded linear JSON reader for complete typed function export envelopes."""
import json
import math
from pathlib import Path
import re
from .typed_transport import FUNCTION_CAPABILITIES as CAPABILITIES, TransportError
TransitionError = TransportError

def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TransitionError('duplicate JSON object key: ' + key)
        result[key] = value
    return result


def _finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise TransitionError('nonfinite JSON value')
    return value


class _JSONStream:
    """Linear byte-boundary scan, then exactly one strict decode per value.

    Structural searches visit disjoint byte ranges. No prefix is decoded again
    when another chunk arrives. Values remain provisional until stream_functions
    exhausts and validates the complete enclosing document and its capabilities.
    """

    CHUNK_BYTES = 65536
    STRUCTURAL = re.compile(rb'["{}\[\]]')
    STRING_SPECIAL = re.compile(rb'["\\]')
    ATOM_END = re.compile(rb'[ \t\r\n,\]}:]')

    def __init__(self, stream, maximum_value_bytes, *, maximum_file_bytes=None):
        self.stream, self.maximum = stream, maximum_value_bytes
        self.maximum_file_bytes, self.read_bytes = maximum_file_bytes, 0
        self.buffer, self.offset, self.eof = b'', 0, False
        self.decoder = json.JSONDecoder(object_pairs_hook=_object,
            parse_float=_finite_float,
            parse_constant=lambda value: (_ for _ in ()).throw(TransitionError('nonfinite JSON value')))

    def more(self):
        if self.offset != len(self.buffer):
            raise TransitionError('internal JSON reader attempted to discard unread bytes')
        self.buffer = self.stream.read(self.CHUNK_BYTES)
        if not isinstance(self.buffer, bytes):
            raise TransitionError('JSON token reader requires a binary stream')
        self.offset = 0
        self.eof = not self.buffer
        self.read_bytes += len(self.buffer)
        if self.maximum_file_bytes is not None and self.read_bytes > self.maximum_file_bytes:
            raise TransitionError('function export exceeds configured file bound while reading')

    def peek(self):
        while True:
            while self.offset < len(self.buffer) and self.buffer[self.offset] in b' \t\n\r':
                self.offset += 1
            if self.offset < len(self.buffer):
                return chr(self.buffer[self.offset])
            if self.eof:
                return ''
            self.more()

    def take(self, token):
        if self.peek() != token:
            raise TransitionError('invalid/truncated JSON envelope; expected ' + token)
        self.offset += 1

    def value(self):
        first = self.peek()
        if not first:
            raise TransitionError('truncated JSON value')
        kind = 'string' if first == '"' else 'container' if first in '{[' else 'atom'
        parts, size, stack = [], 0, bytearray()
        quoted, escaped, complete = False, False, False
        while True:
            start = position = self.offset
            length = len(self.buffer)
            if kind == 'atom':
                boundary = self.ATOM_END.search(self.buffer, position)
                position = boundary.start() if boundary else length
                complete = boundary is not None
            else:
                if escaped and position < length:
                    # The preceding chunk ended with a backslash inside a string.
                    position += 1
                    escaped = False
                while position < length:
                    special = (self.STRING_SPECIAL if quoted else self.STRUCTURAL).search(self.buffer, position)
                    if special is None:
                        position = length
                        break
                    index = special.start()
                    token = self.buffer[index]
                    position = index + 1
                    if quoted:
                        if token == 92:  # backslash; strict decoder checks escape grammar
                            if position < length:
                                position += 1
                            else:
                                escaped = True
                        else:  # unescaped closing quote
                            quoted = False
                            if kind == 'string':
                                complete = True
                                break
                    elif token == 34:
                        quoted = True
                    elif token in (123, 91):
                        stack.append(125 if token == 123 else 93)
                    else:
                        if not stack or stack.pop() != token:
                            raise TransitionError('mismatched JSON container delimiters')
                        if not stack:
                            complete = True
                            break
            size += position - start
            if size > self.maximum:
                raise TransitionError('one JSON value exceeds the configured capture bound')
            parts.append(self.buffer[start:position])
            self.offset = position
            if complete:
                break
            self.more()
            if self.eof:
                if kind != 'atom':
                    raise TransitionError('invalid/truncated JSON value')
                break
        try:
            text = b''.join(parts).decode('utf-8')
            value, end = self.decoder.raw_decode(text)
            if end != len(text):
                raise TransitionError('invalid characters inside JSON value')
            return value
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise TransitionError('invalid/truncated JSON value') from exc


def stream_functions(path, *, maximum_file_bytes=1024**3, maximum_value_bytes=256*1024**2, messages=None):
    """Yield one function at a time and validate the entire JSON envelope.

    Fully exhaust this generator: the capability, error, duplicate-group and
    trailing-content checks also apply to the suffix after the last function.
    Neither indentation nor a fixed number/name of functions is assumed.
    """
    path = Path(path)
    if path.stat().st_size > maximum_file_bytes:
        raise TransitionError('function export exceeds configured file bound')
    with path.open('rb') as stream:
        tokens = _JSONStream(stream, maximum_value_bytes, maximum_file_bytes=maximum_file_bytes)
        tokens.take('[')
        group_count, first = 0, True
        while tokens.peek() != ']':
            if not first:
                tokens.take(',')
            first = False
            tokens.take('{')
            message, fields, field_first, is_functions = {}, set(), True, False
            while tokens.peek() != '}':
                if not field_first:
                    tokens.take(',')
                field_first = False
                key = tokens.value()
                if not isinstance(key, str) or key in fields:
                    raise TransitionError('non-string or duplicate message key')
                fields.add(key)
                tokens.take(':')
                if key == 'functions':
                    group_count += 1
                    if group_count != 1:
                        raise TransitionError('multiple functions groups')
                    is_functions = True
                    tokens.take('[')
                    function_first = True
                    while tokens.peek() != ']':
                        if not function_first:
                            tokens.take(',')
                        function_first = False
                        function = tokens.value()
                        if not isinstance(function, dict):
                            raise TransitionError('function entry is not an object')
                        yield function
                        del function
                    tokens.take(']')
                else:
                    message[key] = tokens.value()
            tokens.take('}')
            if message.get('messageType') == 'ERROR':
                raise TransitionError('backend emitted an ERROR message')
            if is_functions and any(message.get(key) is not value for key, value in CAPABILITIES.items()):
                raise TransitionError('missing complete typed-export capability')
            if messages is not None:
                if is_functions:
                    message['functions'] = None
                messages.append(message)
        tokens.take(']')
        if tokens.peek() or group_count != 1:
            raise TransitionError('trailing JSON content or missing functions group')


