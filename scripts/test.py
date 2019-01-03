import sys
import time
import string
import struct
import random
import argparse
from socket import socket, htons, htonl, ntohs, ntohl, AF_UNIX


ACK = 0x00
PUT = 0x01
GET = 0x02
DEL = 0x03
TTL = 0x04
INC = 0x05
DEC = 0x06
COUNT = 0x07
KEYS = 0x08
QUIT = 0xff


def send_quit(sock):
    quit = struct.pack('=BI', QUIT, htonl(5))
    sock.send(quit);
    return 'done'


def send_keys(sock, key):
    fmt = f'=BIH{len(key)}s'
    count = struct.pack(
        fmt,
        KEYS,
        htonl(7 + len(key)),
        htons(len(key)),
        key.encode()
    )
    sock.send(count)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    key_len = ntohl(struct.unpack('=I', sock.recv(4))[0])
    keys = []
    print(key_len)

    for _ in range(key_len):
        keylen = ntohs(struct.unpack('=H', sock.recv(2))[0])
        keys.append(struct.unpack(f'={keylen}sB', sock.recv(keylen+1))[0])

    return {
        'code': code,
        'total_len': total_len,
        'payload': keys
    }


def send_putbulkrng(sock, n):
    for i in range(n):
        key, value = f'{"".join(random.choices(string.ascii_letters + string.digits, k=random.randint(6, 30)))}', f'value{i}'
        keylen = len(key)
        vallen = len(value)
        put = struct.pack(
            f'=BIHI{keylen}s{vallen}s',
            PUT,
            htonl(11 + keylen + vallen),
            htons(keylen),
            htonl(vallen),
            key.encode(),
            value.encode()
        )
        sock.send(put)
        header = sock.recv(5)
        code, total_len = struct.unpack('=BI', header)
        total_len = ntohl(total_len)
        payload = struct.unpack('=B', sock.recv(total_len - 5))

    return 'done'


def send_putbulk(sock, n):
    for i in range(n):
        key, value = f'key{i}', f'value{i}'
        keylen = len(key)
        vallen = len(value)
        put = struct.pack(
            f'=BIHI{keylen}s{vallen}s',
            PUT,
            htonl(11 + keylen + vallen),
            htons(keylen),
            htonl(vallen),
            key.encode(),
            value.encode()
        )
        sock.send(put)
        header = sock.recv(5)
        code, total_len = struct.unpack('=BI', header)
        total_len = ntohl(total_len)
        payload = struct.unpack('=B', sock.recv(total_len - 5))

    return 'done'


def send_put(sock, key, value, ttl=None, prefix=False):
    keylen = len(key)
    vallen = len(value)
    if not ttl:
        put = struct.pack(
            f'=BIHI{keylen}s{vallen}sB',
            PUT,
            htonl(12 + keylen + vallen),
            htons(keylen),
            htonl(vallen),
            key.encode(),
            value.encode(),
            prefix
        )
    else:
        put = struct.pack(
            f'=BIHI{keylen}s{vallen}sBH',
            PUT,
            htonl(14 + keylen + vallen),
            htons(keylen),
            htonl(vallen),
            key.encode(),
            value.encode(),
            prefix,
            htons(ttl)
        )
    sock.send(put)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = struct.unpack('=B', sock.recv(total_len - 5))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_get(sock, key):
    keylen = len(key)
    get = struct.pack(
        f'=BIH{keylen}s',
        GET,
        htonl(7 + keylen),
        htons(keylen),
        key.encode()
    )
    sock.send(get)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    if code == ACK:
        payload = struct.unpack('=B', sock.recv(total_len - 5))
        data = code
    else:
        datalen = ntohl(struct.unpack('=I', sock.recv(4))[0])
        data = struct.unpack(f'={datalen}s', sock.recv(datalen))[0]

    return {
        'code': code,
        'total_len': total_len,
        'payload': data
    }


def send_ttl(sock, key, ttl):
    keylen = len(key)
    ttl = struct.pack(
        f'=BIH{keylen}sBH',
        TTL,
        htonl(10 + keylen),
        htons(keylen),
        key.encode(),
        0,
        htons(ttl)
    )
    sock.send(ttl)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    if code == ACK:
        payload = struct.unpack('=B', sock.recv(total_len - 5))
    else:
        klen, vlen = struct.unpack('=HI', sock.recv(6))
        klen, vlen = ntohs(klen), ntohl(vlen)
        payload = struct.unpack(f'={klen}s{vlen}s', sock.recv(klen + vlen))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_del(sock, keys, is_prefix=False):
    totlen = sum(len(k) for k in keys)
    fmtinit = '=BII'
    if is_prefix:
        fmt = ''.join(f'H{len(key)}sB' for key in keys)
        totlen += 9 + 3 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode(), is_prefix) for key in keys] for x in t]
    else:
        fmt = ''.join(f'H{len(key)}s' for key in keys)
        totlen += 9 + 2 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode()) for key in keys] for x in t]
    fmt = fmtinit + fmt
    delete = struct.pack(
        fmt,
        DEL,
        htonl(totlen),
        htonl(len(keys)),
        *keys_to_net
    )
    sock.send(delete)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = struct.unpack('=B', sock.recv(total_len - 5))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_inc(sock, keys, inc=True, is_prefix=False):
    opcode = INC if inc else DEC
    totlen = sum(len(k) for k in keys)
    fmtinit = '=BIH'
    if is_prefix:
        fmt = ''.join(f'H{len(key)}sH' for key in keys)
        totlen += 7 + 4 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode(), is_prefix) for key in keys] for x in t]
    else:
        fmt = ''.join(f'H{len(key)}s' for key in keys)
        totlen += 7 + 2 * len(keys)
        keys_to_net = [x for t in [(htons(len(key)), key.encode()) for key in keys] for x in t]
    fmt = fmtinit + fmt
    inc = struct.pack(
        fmt,
        opcode,
        htonl(totlen),
        htons(len(keys)),
        *keys_to_net
    )
    sock.send(inc)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = struct.unpack('=B', sock.recv(total_len - 5))

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


def send_count(sock, key):
    fmt = f'=BIH{len(key)}s'
    count = struct.pack(
        fmt,
        COUNT,
        htonl(7 + len(key)),
        htons(len(key)),
        key.encode()
    )
    sock.send(count)
    header = sock.recv(5)
    code, total_len = struct.unpack('=BI', header)
    total_len = ntohl(total_len)
    payload = ntohl(struct.unpack('=I', sock.recv(total_len - 5))[0])

    return {
        'code': code,
        'total_len': total_len,
        'payload': payload
    }


if __name__ == '__main__':
    if sys.argv[1] and sys.argv[1] == 'local':
        sock = socket(AF_UNIX)
        sock.connect('/tmp/tritedb.sock')
    else:
        sock = socket()
        sock.connect(('127.0.0.1', 9090))
    while True:
        command = input("> ")
        head, tail = command.split(' ', 1)
        if head.lower() == 'put':
            k, v = tail.split()
            print(send_put(sock, k, v))
        elif head.lower() == 'putttl':
            k, v, e = tail.split()
            print(send_put(sock, k, v, int(e)))
        elif head.lower() == 'get':
            print(send_get(sock, tail))
        elif head.lower() == 'ttl' or head.lower() == 'expire':
            k, t = tail.split()
            print(send_ttl(sock, k, int(t)))
        elif head.lower() == 'inc':
            print(send_inc(sock, tail.split()))
        elif head.lower() == 'dec':
            print(send_inc(sock, tail.split(), False))
        elif head.lower() == 'pinc':
            print(send_inc(sock, tail.split(), True, True))
        elif head.lower() == 'pdec':
            print(send_inc(sock, tail.split(), False, True))
        elif head.lower() == 'pdel':
            print(send_del(sock, tail.split(), True))
        elif head.lower() == 'del':
            print(send_del(sock, tail.split()))
        elif head.lower() == 'putbulk':
            print(send_putbulk(sock, int(tail)))
        elif head.lower() == 'putbulkrng':
            print(send_putbulkrng(sock, int(tail)))
        elif head.lower() == 'count':
            print(send_count(sock, tail))
        elif head.lower() == 'keys':
            print(send_keys(sock, tail))
        elif head.lower() == 'pput':
            k, v = tail.split()
            print(send_put(sock, k, v, None, True))
        else:
            print(send_quit(sock))
