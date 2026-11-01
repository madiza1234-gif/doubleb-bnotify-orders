"""Isolated LINE group pairing receiver. Never forwards to another service."""
import base64
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def paired_groups(body, signature, secret, pairing_code):
    if not secret or not pairing_code:
        raise ValueError('not configured')
    expected = base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError('invalid signature')
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get('events'), list):
        raise ValueError('invalid events')
    groups = set()
    for event in payload['events']:
        if not isinstance(event, dict):
            continue
        source, message = event.get('source', {}), event.get('message', {})
        if not isinstance(source, dict) or not isinstance(message, dict):
            continue
        if (event.get('type') == 'message' and source.get('type') == 'group'
                and message.get('type') == 'text'
                and isinstance(message.get('text'), str)
                and hmac.compare_digest(message['text'].strip().encode(), pairing_code.encode())):
            group = source.get('groupId', '')
            if isinstance(group, str) and len(group) == 33 and group.startswith('C'):
                try:
                    int(group[1:], 16)
                except ValueError:
                    continue
                groups.add(group)
    return groups


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log request bodies, headers, message text or credentials.

    def reply(self, status, result):
        body = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != '/healthz':
            return self.reply(404, {'error': 'not found'})
        self.reply(200, {'status': 'ok', 'service': 'bnotify-group-receiver'})

    def do_POST(self):
        if self.path != '/line-webhook':
            return self.reply(404, {'error': 'not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400, {'error': 'invalid length'})
        if length <= 0 or length > 262144:
            return self.reply(413, {'error': 'invalid size'})
        secret = os.environ.get('LINE_CHANNEL_SECRET', '')
        code = os.environ.get('LINE_PAIRING_CODE', '')
        if not secret or not code:
            return self.reply(503, {'error': 'not configured'})
        try:
            groups = paired_groups(self.rfile.read(length), self.headers.get('X-Line-Signature', ''), secret, code)
        except PermissionError:
            return self.reply(401, {'error': 'invalid signature'})
        except (ValueError, TypeError, UnicodeError):
            return self.reply(400, {'error': 'invalid body'})
        for group in sorted(groups):
            # Operator retrieves only the matched group identifier from the new service logs.
            print('BNOTIFY_PAIRED_GROUP=' + group, flush=True)
        self.reply(200, {'ok': True})


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '10000'))), Handler).serve_forever()