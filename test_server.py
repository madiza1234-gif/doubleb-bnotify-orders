import base64
import hashlib
import hmac
import json
import unittest
from server import paired_groups


class ReceiverTests(unittest.TestCase):
    def call(self, payload, code='PAIR-test'):
        body = json.dumps(payload).encode()
        signature = base64.b64encode(hmac.new(b'test-secret', body, hashlib.sha256).digest()).decode()
        return paired_groups(body, signature, 'test-secret', code)

    def event(self, text='PAIR-test', source_type='group'):
        return {'type': 'message', 'source': {'type': source_type, 'groupId': 'C' + '1' * 32},
                'message': {'type': 'text', 'text': text}}

    def test_signed_pair(self):
        self.assertEqual(self.call({'events': [self.event()]}), {'C' + '1' * 32})

    def test_other_messages_ignored(self):
        self.assertEqual(self.call({'events': [self.event('ข้อความลูกค้า'), self.event(source_type='user')]}), set())

    def test_forged_signature_rejected(self):
        with self.assertRaises(PermissionError):
            paired_groups(b'{"events":[]}', 'forged', 'test-secret', 'PAIR-test')

    def test_line_verify_empty_events(self):
        self.assertEqual(self.call({'events': []}), set())

    def test_pairing_disabled(self):
        self.assertEqual(self.call({'events': [self.event()]}, code=''), set())

    def test_missing_configuration(self):
        with self.assertRaises(ValueError):
            paired_groups(b'{}', '', '', '')


if __name__ == '__main__':
    unittest.main()