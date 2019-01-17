import os
import time
import signal
import struct
import unittest
import subprocess
from socket import socket, htons, htonl, ntohl, ntohs


class TriteDBTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.proc = subprocess.Popen(
            ['bin/tritedb'],
            stdout=subprocess.PIPE,
            preexec_fn=os.setsid
        )

        time.sleep(.5)

        cls.connection = socket()
        cls.connection.connect(('127.0.0.1', 9090))

    @classmethod
    def tearDownClass(cls):
        cls.connection.close()
        os.kill(cls.proc.pid, signal.SIGTERM)

    def _send_put(self, key, value):
        keylen = len(key)
        vallen = len(value)

        ttl = False
        prefix = False

        if not ttl:
            put = struct.pack(
                f'=BIBBBHI{keylen}s{vallen}sB',
                0x01,
                htonl(15 + keylen + vallen),
                0x00,
                0x00,
                0x00,
                htons(keylen),
                htonl(vallen),
                key.encode(),
                value.encode(),
                prefix
            )
        else:
            put = struct.pack(
                f'=BIBBBHI{keylen}s{vallen}sBH',
                0x01,
                htonl(17 + keylen + vallen),
                0x00,
                0x00,
                0x00,
                htons(keylen),
                htonl(vallen),
                key.encode(),
                value.encode(),
                prefix,
                htons(ttl)
            )

        self.connection.send(put)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        _ = struct.unpack('=B', self.connection.recv(1))

        return code

    def _send_get(self, key):
        keylen = len(key)
        get = struct.pack(
        f'=BIBBBH{keylen}s',
            0x02,
            htonl(10 + keylen),
            0x00,
            0x00,
            0x00,
            htons(keylen),
            key.encode()
        )
        self.connection.send(get)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
            data = code
        else:
            datalen = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
            data = struct.unpack(f'={datalen}s', self.connection.recv(datalen))[0]

        return data

    def _send_del(self, keys):
        is_prefix = False
        totlen = sum(len(k) for k in keys)
        fmtinit = '=BIBBBI'
        fmt = ''.join(f'H{len(key)}sB' for key in keys)
        totlen += 12 + 3 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode(), is_prefix) for key in keys] for x in t]
        fmt = fmtinit + fmt
        delete = struct.pack(
            fmt,
            0x03,
            htonl(totlen),
            0x00,
            0x00,
            0x00,
            htonl(len(keys)),
            *keys_to_net
        )
        self.connection.send(delete)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        payload = struct.unpack('=B', self.connection.recv(total_len - 8))

        return code

    def test_put(self):
        key = "test-key-1"
        value = "test-value-1"

        code = self._send_put(key, value)

        self.assertEqual(code, 0x00)

        self._send_del([key])

    def test_get(self):
        self._send_put("test-key-1", "test-value-1")
        key = "test-key-1"
        keylen = len(key)
        get = struct.pack(
        f'=BIBBBH{keylen}s',
            0x02,
            htonl(10 + keylen),
            0x00,
            0x00,
            0x00,
            htons(keylen),
            key.encode()
        )
        self.connection.send(get)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
            data = code
        else:
            datalen = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
            data = struct.unpack(f'={datalen}s', self.connection.recv(datalen))[0]

        self.assertEqual(data, b"test-value-1")

        self._send_del([key])

    def test_count(self):
        key = "key"
        fmt = f'=BIBBBH{len(key)}s'
        count = struct.pack(
            fmt,
            0x07,
            htonl(10 + len(key)),
            0x00,
            0x00,
            0x00,
            htons(len(key)),
            key.encode()
        )
        self.connection.send(count)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        payload = ntohl(struct.unpack('=I', self.connection.recv(total_len - 8))[0])

        self.assertEqual(code, 0x00)
        self.assertEqual(payload, 0)

    def test_del(self):
        self._send_put('key-1', 'value-1')
        keys = ['key']
        is_prefix = True
        totlen = sum(len(k) for k in keys)
        fmtinit = '=BIBBBI'
        if is_prefix:
            fmt = ''.join(f'H{len(key)}sB' for key in keys)
            totlen += 12 + 3 * len(keys)
            keys_to_net = [x for t in [(htons(len(key)), key.encode(), is_prefix) for key in keys] for x in t]
        else:
            fmt = ''.join(f'H{len(key)}s' for key in keys)
            totlen += 12 + 2 * len(keys)
            keys_to_net = [x for t in [(htons(len(key)), key.encode()) for key in keys] for x in t]
        fmt = fmtinit + fmt
        delete = struct.pack(
            fmt,
            0x03,
            htonl(totlen),
            0x00,
            0x00,
            0x00,
            htonl(len(keys)),
            *keys_to_net
        )
        self.connection.send(delete)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        payload = struct.unpack('=B', self.connection.recv(total_len - 8))

        self.assertEqual(code, 0x00)

    def test_keys(self):
        self._send_put('key1', 'value1')
        self._send_put('key2', 'value2')
        self._send_put('key3', 'value3')
        key = 'key'
        fmt = f'=BIBBBH{len(key)}s'
        keys = struct.pack(
            fmt,
            0x08,
            htonl(10 + len(key)),
            0x00,
            0x00,
            0x00,
            htons(len(key)),
            key.encode()
        )
        self.connection.send(keys)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        key_len = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
        keys = []

        for _ in range(key_len):
            keylen = ntohs(struct.unpack('=H', self.connection.recv(2))[0])
            keys.append(struct.unpack(f'={keylen}sB', self.connection.recv(keylen+1))[0])

        self.assertEqual(code, 0x00)
        self.assertEqual(len(keys), 3)
        self.assertEqual(keys, [b'key1', b'key2', b'key3'])

        self._send_del(['key1', 'key2', 'key3'])

    def test_ttl(self):
        self._send_put('ttlkey', 'value')
        key = 'ttlkey'
        ttl = 2
        keylen = len(key)
        ttl = struct.pack(
            f'=BIBBBH{keylen}sBH',
            0x04,
            htonl(13 + keylen),
            0x00,
            0x00,
            0x00,
            htons(keylen),
            key.encode(),
            0,
            htons(ttl)
        )
        self.connection.send(ttl)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
        else:
            klen, vlen = struct.unpack('=HI', self.connection.recv(6))
            klen, vlen = ntohs(klen), ntohl(vlen)
            payload = struct.unpack(f'={klen}s{vlen}s', self.connection.recv(klen + vlen))

        self.assertEqual(code, 0x00)

        data = self._send_get(key)

        self.assertEqual(data, b'value')

        time.sleep(2)

        data = self._send_get(key)

        self.assertEqual(data, 0)

        self._send_del([key])

    def test_inc(self):
        self._send_put('inc-key', '9')
        keys = ['inc-key']
        totlen = sum(len(k) for k in keys)
        fmtinit = '=BIBBBI'
        is_prefix = False
        fmt = ''.join(f'H{len(key)}sB' for key in keys)
        totlen += 12 + 3 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode(), is_prefix) for key in keys] for x in t]
        fmt = fmtinit + fmt
        inc = struct.pack(
            fmt,
            0x05,
            htonl(totlen),
            0x00,
            0x00,
            0x00,
            htonl(len(keys)),
            *keys_to_net
        )
        self.connection.send(inc)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        payload = struct.unpack('=B', self.connection.recv(total_len - 8))

        self.assertEqual(code, 0x00)

        data = self._send_get('inc-key')

        self.assertEqual(data, b'10')

        self._send_del(keys)

    def test_put_bulk(self):

        kvs = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': 'value3',
            'key4': 'value4',
            'key5': 'value5'
        }

        prefix = False

        fmt = ''.join(f'HI{len(key)}s{len(val)}sBH' for key, val in kvs.items())

        keysval = [x for t in [(htons(len(k)), htonl(len(v)), k.encode(), v.encode(), prefix, htons(0)) for k, v in kvs.items()] for x in t]

        totlen = 12 + 9 * len(kvs) + sum(len(k) + len(v) for k, v in kvs.items())

        put = struct.pack(
            f'=BIBBBI' + fmt,
            0x01,
            htonl(totlen),
            0x01,
            0x00,
            0x00,
            htonl(len(kvs)),
            *keysval
        )

        self.connection.send(put)
        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        _ = struct.unpack('=B', self.connection.recv(1))

        self.assertEqual(code, 0x00)

        self.assertEqual(self._send_get('key1'), b'value1')

        self._send_del(kvs.keys())

    def test_use(self):

        db = struct.pack('=BIBBB', 0xfd, htonl(8), 0x00, 0x00, 0x00)
        self.connection.send(db)

        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
            payload = code
        else:
            datalen = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
            payload = struct.unpack(f'={datalen}s', self.connection.recv(datalen))[0]

        self.assertEqual(code, 0x01)
        self.assertEqual(payload, b'db0')

        dbname = "test-database"

        use = struct.pack(
            f'=BIBBBH{len(dbname)}s',
            0x09,
            htonl(10 + len(dbname)),
            0x00,
            0x00,
            0x00,
            htons(len(dbname)),
            dbname.encode()
        )

        self.connection.send(use)

        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        _ = struct.unpack('=B', self.connection.recv(1))

        self.assertEqual(code, 0x00)

        db = struct.pack('=BIBBB', 0xfd, htonl(8), 0x00, 0x00, 0x00)
        self.connection.send(db)

        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
            payload = code
        else:
            datalen = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
            payload = struct.unpack(f'={datalen}s', self.connection.recv(datalen))[0]

        self.assertEqual(code, 0x01)
        self.assertEqual(payload, dbname.encode())

        defaultdb = "db0"

        use = struct.pack(
            f'=BIBBBH{len(defaultdb)}s',
            0x09,
            htonl(10 + len(defaultdb)),
            0x00,
            0x00,
            0x00,
            htons(len(defaultdb)),
            defaultdb.encode()
        )

        self.connection.send(use)

        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        _ = struct.unpack('=B', self.connection.recv(1))

        self.assertEqual(code, 0x00)

        db = struct.pack('=BIBBB', 0xfd, htonl(8), 0x00, 0x00, 0x00)
        self.connection.send(db)

        header = self.connection.recv(8)
        code, total_len, _, _, _ = struct.unpack('=BIBBB', header)
        total_len = ntohl(total_len)
        if code == 0x00:
            payload = struct.unpack('=B', self.connection.recv(total_len - 8))
            payload = code
        else:
            datalen = ntohl(struct.unpack('=I', self.connection.recv(4))[0])
            payload = struct.unpack(f'={datalen}s', self.connection.recv(datalen))[0]

        self.assertEqual(code, 0x01)
        self.assertEqual(payload, defaultdb.encode())
